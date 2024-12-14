<?php

/**
 * Repositorio {@link https://github.com/yordanny90/SecureStr}
 *
 */
class SecureStr{

    private function __construct(){ }

    /**
     * Convierte un valor base64 normal para ser compatible con urls
     * @param string $base64
     * @return string
     */
    static function base64_toUrl($base64){
        return str_replace(array('+','/','=',"\n","\r"),array('-','_','','',''),$base64);
    }

    /**
     * Convierte un valor base64 compatible con urls a su valor base64 normal
     * @param string $base64_url
     * @return string
     */
    static function base64_fromUrl($base64_url){
        $b64=str_replace(array('-','_'),array('+','/'),$base64_url);
        if((strlen($b64)%4)>1){
            $b64.=str_repeat('=', 4-(strlen($b64)%4));
        }
        return $b64;
    }

    private static function makeCheckSum(string $data, string $privatekey, string $salt, int $iterations, int $length): ?string{
        if(!($key=openssl_pbkdf2($privatekey, $salt, 32, $iterations, 'sha256'))) return null;
        if(!($hash=hash_hmac('sha256', $data, $key, true))) return null;
        if(!($hash=substr($hash, 0, $length))) return null;
        return $hash;
    }

    /**
     * @param string $data
     * @param string $privatekey
     * @param int $length Default: 26. Rango: 26-42. Longitud del checksum resultante en bytes
     * @param int|null $iterations Default: 26. Rango: 255-65535. Iteraciones usadas en {@see openssl_pbkdf2()} Si es null, se asigna <code>rand(255, 2560)</code>
     * @param bool $raw
     * @return string|null
     */
    public static function checksum_create(string $data, string $privatekey, int $length=26, ?int $iterations=null, bool $raw=false): ?string{
        $length=min(max($length-10, 16), 32);
        if($iterations===null) $iterations=rand(255, 2560);
        elseif($iterations>65535) $iterations=65535;
        elseif($iterations<255) $iterations=255;
        $salt=pack('n', $iterations).openssl_random_pseudo_bytes(8);
        $check=self::makeCheckSum($data, $privatekey, $salt, $iterations, $length);
        if(!$check) return null;
        return $raw?$salt.$check:self::base64_toUrl(base64_encode($salt.$check));
    }

    /**
     * @param string $data Dato a comprobar
     * @param string $privatekey
     * @param string $checksum Valor generado por {@see SecureStr::checksum_create()}
     * @param bool $raw
     * @return bool
     */
    public static function checksum_verify(string $data, string $privatekey, string $checksum, bool $raw=false): bool{
        if(!$raw) $checksum=base64_decode(self::base64_fromUrl($checksum));
        $length=strlen($checksum)-10;
        if($length<16 || $length>32) return false;
        $iterations=unpack('n', substr($checksum, 0, 2))[1]??0;
        if($iterations<255) return false;
        $salt=substr($checksum, 0, 10);
        $check=self::makeCheckSum($data, $privatekey, $salt, $iterations, $length);
        if(!$check || $check!==substr($checksum, 10)) return false;
        return true;
    }

    /**
     * Genera un valor con checksum seguro (base64), utilizando una llave privada de codificación
     * @param string $value
     * @param string $privatekey Llave privada
     * @param int $length Default: 26. Rango: 26-42. Longitud del checksum en bytes
     * @return string|null
     * @see SecureStr::decode()
     */
    static function encode(string $value, string $privatekey, int $length=26): ?string{
        $check=self::checksum_create($value, $privatekey, $length);
        if(!is_string($check)) return null;
        $res=$check.'.'.$value;
        return $res;
    }

    /**
     * @param string $encValue
     * @param string $privatekey Llave privada
     * @return string|null Valor original si es válido.
     */
    static function decode(string $encValue, string $privatekey): ?string{
        $parts=[];
        list($parts['checksum'], $parts['value'])=explode('.', $encValue, 2);
        if(!isset($parts['value'])) return null;
        if(!self::checksum_verify($parts['value'], $privatekey, $parts['checksum'])) return null;
        return $parts['value'];
    }

    /**
     * Encripta el valor por capas usando AES-128-OFB, añade un checksum para comprobar la integridad del dato al desencriptar
     * y permite el uso de una llave de cualquier longitud
     *
     * - Cada 16 bytes de la llave, agrega una capa de encriptación
     * - Se recomienda el uso de llaves de 2 a 4 niveles (32 a 64 bytes)
     * - Cuanto más grande sea la llave, mayor será la protección del dato, pero disminuye la eficiencia del resultado
     * Usa {@see SecureStr::strong_decrypt_AES128()} para desencriptar
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    public static function strong_encrypt_AES128(string $value, string $strongKey, bool $raw=false, int $levels=0){
        return static::strong_encrypt_AESx(128, $value, $strongKey, $raw, $levels);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::strong_encrypt_AES128()}
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    public static function strong_decrypt_AES128(string $value, string $strongKey, bool $raw=false, int $levels=0){
        return static::strong_decrypt_AESx(128, $value, $strongKey, $raw, $levels);
    }

    /**
     * Encripta el valor por capas usando AES-192-OFB, añade un checksum para comprobar la integridad del dato al desencriptar
     * y permite el uso de una llave de cualquier longitud
     *
     * - Cada 24 bytes de la llave, agrega una capa de encriptación
     * - Se recomienda el uso de llaves de 2 a 4 niveles (24 a 96 bytes)
     * - Cuanto más grande sea la llave, mayor será la protección del dato, pero disminuye la eficiencia del resultado
     * Usa {@see SecureStr::strong_decrypt_AES192()} para desencriptar
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    public static function strong_encrypt_AES192(string $value, string $strongKey, bool $raw=false, int $levels=0){
        return static::strong_encrypt_AESx(192, $value, $strongKey, $raw, $levels);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::strong_encrypt_AES192()}
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    public static function strong_decrypt_AES192(string $value, string $strongKey, bool $raw=false, int $levels=0){
        return static::strong_decrypt_AESx(192, $value, $strongKey, $raw, $levels);
    }

    /**
     * Encripta el valor por capas usando AES-256-OFB, añade un checksum para comprobar la integridad del dato al desencriptar
     * y permite el uso de una llave de cualquier longitud
     *
     * - Cada 32 bytes de la llave, agrega una capa de encriptación
     * - Se recomienda el uso de llaves de 2 a 4 niveles (64 a 128 bytes)
     * - Cuanto más grande sea la llave, mayor será la protección del dato, pero disminuye la eficiencia del resultado
     * Usa {@see SecureStr::strong_decrypt_AES256()} para desencriptar
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    public static function strong_encrypt_AES256(string $value, string $strongKey, bool $raw=false, int $levels=0){
        return static::strong_encrypt_AESx(256, $value, $strongKey, $raw, $levels);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::strong_encrypt_AES256()}
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    public static function strong_decrypt_AES256(string $value, string $strongKey, bool $raw=false, int $levels=0){
        return static::strong_decrypt_AESx(256, $value, $strongKey, $raw, $levels);
    }

    private static function key_stronger(string $key, string $salt, int $keySize, int $levels){
        $key_length=max($levels*$keySize, intval(ceil(strlen($key)/$keySize)*$keySize));
        $key_length-=strlen($key);
        if($key_length>0){
            $iterations=1024+$key_length*$levels;
            $key.=openssl_pbkdf2($key, $salt, $key_length, $iterations, 'sha256');
        }
        return $key;
    }

    /**
     * @param int $bits
     * @param string $value
     * @param string $strongKey
     * @param bool $raw
     * @param int $levels Recomendado: 2 a 4 niveles. Autocompleta los niveles de encriptación
     * @return string|null
     * @deprecated
     */
    private static function strong_encrypt_AESx(int $bits, string $value, string $strongKey, bool $raw, int $levels){
        $algo='AES-'.$bits.'-OFB';
        $kSize=($bits/8);
        $ivLen=16;
        $iv=$iv_init=openssl_random_pseudo_bytes($ivLen);
        if($levels>0){
            $strongKey=self::key_stronger($strongKey, $iv_init, $kSize, $levels);
        }
        $c_keys=intval(ceil(strlen($strongKey)/$kSize))?:1;
        $lenFill=(3-(strlen($value)%3))%3;
        $fill=chr((rand(0,63)<<2)|$lenFill);
        if($lenFill>0) $fill.=openssl_random_pseudo_bytes($lenFill);
        $offCheck=(ord($fill)>>2)&15;
        $check=substr(hash_hmac('sha256', $value, $fill.$iv_init, true), $offCheck, 16);
        $comp=[];
        $ivArr=[];
        for($i=0; $i<$c_keys; ++$i){
            $comp[]=substr($check, $i*4, 4);
            $iv=hash('sha256', $iv.$comp[$i], true);
            $ivArr[]=substr($iv, 0, 16);
        }
        $enc_bin=$fill.$value.substr($check, $i*4);
        if(count($ivArr)>$c_keys) array_pop($ivArr);
        $ivArr=array_reverse($ivArr);
        $comp=array_reverse($comp);
        for($i=0; $i<$c_keys; ++$i){
            $enc_bin=openssl_encrypt($enc_bin, $algo, substr($strongKey, $i*$kSize, $kSize), OPENSSL_RAW_DATA, $ivArr[$i]);
            if($enc_bin===false) return null;
            $enc_bin=($comp[$i]??'').$enc_bin;
        }
        return $raw?$iv_init.$enc_bin:base64_encode($iv_init.$enc_bin);
    }

    /**
     * @param int $bits
     * @param string $enc_value
     * @param string $strongKey
     * @param bool $raw
     * @param int $levels
     * @return false|string|null
     * @deprecated
     */
    private static function strong_decrypt_AESx(int $bits, string $enc_value, string $strongKey, bool $raw, int $levels){
        $algo='AES-'.$bits.'-OFB';
        $kSize=($bits/8);
        $enc_bin=$raw?$enc_value:base64_decode($enc_value);
        if($enc_bin===false) return null;
        $ivLen=16;
        $iv=$iv_init=substr($enc_bin, 0, $ivLen);
        $enc_bin=substr($enc_bin, $ivLen);
        if($levels>0){
            $strongKey=self::key_stronger($strongKey, $iv_init, $kSize, $levels);
        }
        $keys=str_split($strongKey, $kSize);
        $check='';
        foreach(array_reverse($keys) AS $key){
            if(strlen($check)<16){
                $c_i=substr($enc_bin, 0, 4);
                $check.=$c_i;
                $enc_bin=substr($enc_bin, 4);
            }
            else{
                $c_i='';
            }
            $iv=hash('sha256', $iv.$c_i, true);
            $enc_bin=openssl_decrypt($enc_bin, $algo, $key, OPENSSL_RAW_DATA, substr($iv, 0, 16));
            if($enc_bin===false) return null;
        }
        $rest=16-strlen($check);
        if($rest>0){
            $check.=substr($enc_bin, -$rest);
            $enc_bin=substr($enc_bin, 0, -$rest);
        }
        $ctrl=ord($enc_bin[0]);
        $offCheck=(($ctrl>>2)&15);
        $lenFill=1+($ctrl&3);
        $fill=substr($enc_bin, 0, $lenFill);
        $value=substr($enc_bin, $lenFill);
        $check0=substr(hash_hmac('sha256', $value, $fill.$iv_init, true), $offCheck, 16);
        if($check0!==$check)
            return null;
        return $value;
    }

    /**
     * Método de encriptación por niveles. Más eficiente que {@see SecureStr::strong_encrypt_AESx()}
     * @param string $value Valor a encriptar
     * @param string $key Llave inicial de encriptación. El proceso genera nuevos valores en cada iteración
     * @param bool $raw Default=FALSE. Devuelve un base64. Si es TRUE, devuelve el valor binario
     * @param int $iterations [1-65536] Números de iteraciones. Ver {@see openssl_pbkdf2()}
     * @param int $saltLength [8-32] Default=16 Longitud del salt agregado al resultado
     * @return string
     * @throws Exception
     */
    public static function encrypt_derive256(string $value, string $key, bool $raw=false, int $iterations, int $saltLength=16){
        $digest_algo='sha256';
        $keyLen=32;
        $ivLen=16;
        $saltLength=min(max($saltLength, 8), 32);
        $iterations=min(max($iterations, 1), 65536);
        $salt=openssl_random_pseudo_bytes($saltLength);
        if(!$salt) throw new Exception('Random IV Fail');
        $fill=3-((strlen($value)+$saltLength+19)%3);
        $value=openssl_random_pseudo_bytes($fill).$value;
        $checksum=substr(hash_hmac($digest_algo, $value, $salt, true), 0, 16);
        $derivedKey=openssl_pbkdf2($key, hash_hmac($digest_algo, $salt.$checksum, $key, true), $keyLen+$ivLen, $iterations, $digest_algo);
        if($derivedKey===false) throw new Exception('PBKDF2 Fail');
        $enc_bin=openssl_encrypt($value, 'aes-256-ofb', substr($derivedKey, $ivLen), OPENSSL_RAW_DATA, substr($derivedKey, 0, $ivLen));
        if($enc_bin===false) throw new Exception('Encrypt Fail');
        $enc_bin=pack('n', $iterations-1).chr(($saltLength-1)<<3|$fill).$salt.$checksum.$enc_bin;
        return $raw?$enc_bin:base64_encode($enc_bin);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::encrypt_derive256()}
     * @param string $enc_value Valor encriptado
     * @param string $key Llave inicial de encriptación
     * @param bool $raw Default=FALSE. Recibe un base64. Si es TRUE, recibe el valor binario
     * @param int|null $iterations
     * @param int|null $saltLength
     * @return string|null
     * @throws Exception
     */
    public static function decrypt_derive256(string $enc_value, string $key, bool $raw=false, ?int &$iterations=null, ?int &$saltLength=null){
        if(!self::explain_derive256($enc_value, $raw, $iterations, $fill, $salt, $checksum, $bin))
            return null;
        $saltLength=strlen($salt);
        $digest_algo='sha256';
        $keyLen=32;
        $ivLen=16;
        $derivedKey=openssl_pbkdf2($key, hash_hmac($digest_algo, $salt.$checksum, $key, true), $keyLen+$ivLen, $iterations, $digest_algo);
        if($derivedKey===false) throw new Exception('PBKDF2 Fail');
        $dec_bin=openssl_decrypt($bin, 'aes-256-ofb', substr($derivedKey, $ivLen), OPENSSL_RAW_DATA, substr($derivedKey, 0, $ivLen));
        if($dec_bin===false) throw new Exception('Decrypt Fail');
        $checksumB=substr(hash_hmac($digest_algo, $dec_bin, $salt, true), 0, 16);
        $dec_bin=substr($dec_bin, $fill);
        if($dec_bin===false || $checksum!==$checksumB)
            return null;
        return $dec_bin;
    }

    public static function explain_derive256(string $val, bool $raw=false, ?int &$iterations=null, ?int &$fill=null, ?string &$salt=null, ?string &$checksum=null, ?string &$bin=null){
        if(!$raw) $val=base64_decode($val);
        if(strlen($val)%3)
            return false;
        $iterations=unpack('n', $val)[1]+1;
        $ctrl=ord(substr($val, 2, 1));
        $saltLen=($ctrl>>3)+1;
        if($saltLen<8)
            return false;
        $fill=$ctrl&7;
        if(1>$fill || $fill>3)
            return false;
        $salt=substr($val, 3, $saltLen);
        $checksum=substr($val, $saltLen+3, 16);
        $bin=substr($val, $saltLen+19);
        if(strlen($bin)<$fill)
            return false;
        return true;
    }

}
