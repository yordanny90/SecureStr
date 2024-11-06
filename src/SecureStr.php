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

    /**
     * Genera un MD5 en base64
     * @param $data
     * @return string
     */
    static function md5_base64($data){
        return self::base64_toUrl(base64_encode(md5($data,true)));
    }

    /**
     * Genera un MD5 HMAC en base64
     * @param string $data
     * @param string $key
     * @return string|null
     */
    static function md5hmac_base64($data, $key){
        $res=hash_hmac('md5', $data, $key, true);
        if(!is_string($res)) return null;
        return self::base64_toUrl(base64_encode($res));
    }

    private static function makeCheckSum(string $value, string $privatekey, string $salt, int $key_length=32, $iterations=1024){
        $key=openssl_pbkdf2($privatekey, $salt, $key_length, $iterations, 'sha256');
        if(!$key) return null;
        $data=hash_hmac('sha256', $value, $privatekey.$key, true);
        if(!$data) return null;
        return $data;
    }

    /**
     * Genera un valor con checksum seguro (base64), utilizando una llave privada de codificación
     * @param string $value
     * @param string $privatekey Llave privada
     * @return string
     * @see SecureStr::decode()
     */
    static function encode(string $value, string $privatekey){
        return self:: encode_x($value, $privatekey);
    }

    /**
     * Genera un valor con checksum seguro (base64), utilizando una llave privada de codificación
     * @param string $value
     * @param string $privatekey Llave privada
     * @param int $level Default: 2. Rango: 1-4. Nivel del checksum. Longitud por nivel (en bytes):<br>
     * 1: Salt=4 Checksum=8 Total=12<br>
     * 2: Salt=8 Checksum=16 Total=24<br>
     * 3: Salt=12 Checksum=24 Total=36<br>
     * 4: Salt=16 Checksum=32 Total=48<br>
     * El nivel 1 es más susceptible a colisiones, el nivel 4 es el más seguro pero de mayor peso
     * @return string
     * @see SecureStr::decode()
     */
    private static function encode_x(string $value, string $privatekey, int $level=2){
        $c=$level*8;
        $salt=openssl_random_pseudo_bytes($c/2);
        $check=self::makeCheckSum($value, $privatekey, $salt, $c*2);
        if(!is_string($check)) return null;
        $check=substr($check, 0, $c);
        $checksum=self::base64_toUrl(base64_encode($check.$salt));
        $res=$checksum.'.'.$value;
        return $res;
    }

    /**
     * @param string $encValue
     * @param string $privatekey Llave privada
     * @return string|null Valor original si es válido.
     */
    static function decode(string $encValue, string $privatekey){
        $parts=[];
        list($parts['checksum'], $parts['value'])=explode('.', $encValue, 2);
        if(!isset($parts['value'])) return null;
        $check=base64_decode(self::base64_fromUrl($parts['checksum']));
        if(!$check) return null;
        $c=intval(strlen($check)*2/24)*8;
        if($c<8) return null;
        $salt=substr($check, $c);
        $check=substr($check, 0, $c);
        $checksum=substr(self::makeCheckSum($parts['value'], $privatekey, $salt, $c*2), 0, $c);
        if($check!==$checksum) return null;
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

}
