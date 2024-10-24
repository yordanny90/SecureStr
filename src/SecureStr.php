<?php

/**
 * Repositorio {@link https://github.com/yordanny90/SecureStr}
 *
 */
class SecureStr{

    /**
     * Llave privada de seguridad<br>
     * NUNCA se debe publicar esta información
     * @var null
     */
    public static $DEFAULT_PRIVATEKEY=null;

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

    private static function makeCheckSum($value, $group, $privatekey, $subkey){
        return self::md5_base64($privatekey.'.'.$group.'.'.$value.'.'.$group.'.'.$subkey);
    }

    /**
     * Genera un valor con checksum seguro (base64), utilizando una llave privada de codificación
     *
     * > Es compatible con el encode/decode del SecureValue (Versión 1) sin encriptación
     * @param string $value
     * @param string $group Token público. Se adjunta al checksum generado. Se elimina cualquier caracter '.' que contenga.<br>
     * <b>Nota:</b> <i>Puede utilizarse como una comprobación adicional, para evitar que se procese un SecureValue con un token distinto al esperado.<br>
     * Esta comprobación se realiza en la función decode()</i>
     * @param string|null $privatekey Opcional. Si no especifica, se utiliza la llave privada por defecto
     * @param string $subkey Opcional. Llave privada secundaria. Cambia la codificación y decodificación del valor sin modificar la llave privada.
     * @return string
     * @see SecureStr::simple_decode()
     */
    static function simple_encode(string $value, string $group='', ?string $privatekey=null, string $subkey=''){
        if(!is_string($privatekey)) $privatekey=self::$DEFAULT_PRIVATEKEY;
        if(!is_string($privatekey)) return null;
        if(!is_string($subkey)) $subkey='';
        if(!is_string($value)) $value.='';
        if(!is_string($group)) $group='';
        $group=str_replace('.', '', $group);
        $checksum=self::makeCheckSum($value, $group, $privatekey,$subkey);
        if(!is_string($checksum)) return null;
        $res=implode('.', [$checksum, $group, $value]);
        return $res;
    }

    /**
     * > Es compatible con el encode/decode del SecureValue (Versión 1) sin encriptación
     * @param string $secureValue
     * @param string|null $verify_group Opcional. Si se recibe un string, se comprobará que este token fue el utilizado para generar el SecureValue.
     * @param string|null $privatekey Opcional. Si no especifica, se utiliza la llave privada por defecto
     * @param string|null $subkey Opcional. Llave privada secundaria. Cambia la codificación y decodificación del valor sin modificar la llave privada.
     * @return string|null SecureValue si es válido.
     */
    static function simple_decode(string $secureValue, ?string $verify_group=null, ?string $privatekey=null, ?string $subkey=''){
        if(!is_string($privatekey)) $privatekey=self::$DEFAULT_PRIVATEKEY;
        if(!is_string($privatekey)) return null;
        if(!is_string($subkey)) $subkey='';
        $parts=self::simple_explain($secureValue);
        if(!isset($parts['value'])) return null;
        if(is_string($verify_group) && ($parts['group']!==str_replace('.', '', $verify_group))) return null;
        if($parts['checksum']!==self::makeCheckSum($parts['value'], $parts['group'], $privatekey, $subkey)) return null;
        return $parts['value'];
    }

    /**
     * Devuelve las partes del SecureValue:
     * - checksum
     * - group
     * - value
     * @param string $secureValue
     * @return array
     */
    static function simple_explain(string $secureValue){
        $parts=[];
        list($parts['checksum'], $parts['group'], $parts['value'])=explode('.', $secureValue, 3);
        return $parts;
    }

    /**
     * Encripta el valor por capas usando AES-128-OFB, añade un checksum para conprobar la integridad del dato al desencriptar
     * y permite el uso de una llave de cualquier longitud
     *
     * - Cada 16 bytes de la llave, agrega una capa de encriptación
     * - Se recomienda el uso de llaves de 2 a 4 niveles (32 a 64 bytes)
     * - Cuanto más grande sea la llave, mayor será la protección del dato, pero disminuye la eficiencia del resultado
     * Usa {@see SecureStr::strong_decrypt128()} para desencriptar
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @return string|null
     */
    public static function strong_encrypt128(string $value, string $strongKey, bool $raw=false){
        return static::strong_encrypt_x(128, $value, $strongKey, $raw);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::strong_encrypt128()}
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @return string|null
     */
    public static function strong_decrypt128(string $value, string $strongKey, bool $raw=false){
        return static::strong_decrypt_x(128, $value, $strongKey, $raw);
    }

    /**
     * Encripta el valor por capas usando AES-192-OFB, añade un checksum para conprobar la integridad del dato al desencriptar
     * y permite el uso de una llave de cualquier longitud
     *
     * - Cada 24 bytes de la llave, agrega una capa de encriptación
     * - Se recomienda el uso de llaves de 2 a 4 niveles (24 a 96 bytes)
     * - Cuanto más grande sea la llave, mayor será la protección del dato, pero disminuye la eficiencia del resultado
     * Usa {@see SecureStr::strong_decrypt192()} para desencriptar
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @return string|null
     */
    public static function strong_encrypt192(string $value, string $strongKey, bool $raw=false){
        return static::strong_encrypt_x(192, $value, $strongKey, $raw);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::strong_encrypt192()}
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @return string|null
     */
    public static function strong_decrypt192(string $value, string $strongKey, bool $raw=false){
        return static::strong_decrypt_x(192, $value, $strongKey, $raw);
    }

    /**
     * Encripta el valor por capas usando AES-256-OFB, añade un checksum para conprobar la integridad del dato al desencriptar
     * y permite el uso de una llave de cualquier longitud
     *
     * - Cada 32 bytes de la llave, agrega una capa de encriptación
     * - Se recomienda el uso de llaves de 2 a 4 niveles (64 a 128 bytes)
     * - Cuanto más grande sea la llave, mayor será la protección del dato, pero disminuye la eficiencia del resultado
     * Usa {@see SecureStr::strong_decrypt256()} para desencriptar
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @return string|null
     */
    public static function strong_encrypt256(string $value, string $strongKey, bool $raw=false){
        return static::strong_encrypt_x(256, $value, $strongKey, $raw);
    }

    /**
     * Desencripta el valor generado por {@see SecureStr::strong_encrypt256()}
     * @param string $value
     * @param string $strongKey La llave se lee en binario, un valor en base64 no se decodifica
     * @param bool $raw
     * @return string|null
     */
    public static function strong_decrypt256(string $value, string $strongKey, bool $raw=false){
        return static::strong_decrypt_x(256, $value, $strongKey, $raw);
    }

    /**
     * @param int $bits
     * @param string $value
     * @param string $strongKey
     * @param bool $raw
     * @return string|null
     */
    private static function strong_encrypt_x(int $bits, string $value, string $strongKey, bool $raw=false){
        $algo='AES-'.$bits.'-OFB';
        $kSize=($bits/8);
        $ivLen=13;
        $iv=$iv_init=chr((rand(0,15)<<4)|$ivLen).openssl_random_pseudo_bytes($ivLen-1);
        $c_keys=intval(ceil(strlen($strongKey)/$kSize))?:1;
        $lenFill=(3-((strlen($value))%3));
        $offCheck=rand(0,15);
        $fill=chr(($offCheck<<4)|$lenFill).openssl_random_pseudo_bytes($lenFill);
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

    private static function strong_decrypt_x(int $bits, string $enc_value, string $strongKey, bool $raw=false){
        $algo='AES-'.$bits.'-OFB';
        $kSize=($bits/8);
        $enc_bin=$raw?$enc_value:base64_decode($enc_value);
        if($enc_bin===false) return null;
        $ivLen=ord($enc_bin[0])&15;
        $iv=$iv_init=substr($enc_bin, 0, $ivLen);
        $enc_bin=substr($enc_bin, $ivLen);
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
        $offCheck=($ctrl>>4);
        $lenFill=1+($ctrl&15);
        $fill=substr($enc_bin, 0, $lenFill);
        $value=substr($enc_bin, $lenFill);
        $check0=substr(hash_hmac('sha256', $value, $fill.$iv_init, true), $offCheck, 16);
        if($check0!==$check)
            return null;
        return $value;
    }

}
