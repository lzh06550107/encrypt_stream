<?php
namespace Jsq\EncryptionStreams;

use InvalidArgumentException as Iae;
use LogicException;

/**
 * AES的基本要求是，采用对称分组密码体制，密钥的长度最少支持为128、192、256，分组长度128位
 *
 * @package Jsq\EncryptionStreams
 */

class Cbc implements CipherMethod
{
    const BLOCK_SIZE = 16;

    /**
     * @var string
     */
    private $baseIv; // 初始向量值

    /**
     * @var string
     */
    private $iv; // 非初始向量值

    /**
     * @var int
     */
    private $keySize; // 密钥长度

    public function __construct(string $iv, int $keySize = 256)
    {
        $this->baseIv = $this->iv = $iv; // 初始化向量(iv)
        $this->keySize = $keySize; // 密钥长度

        if (strlen($iv) !== openssl_cipher_iv_length($this->getOpenSslName())) {
            throw new Iae('Invalid initialization vector');
        }
    }

    public function getOpenSslName(): string
    {
        return "aes-{$this->keySize}-cbc";
    }

    public function getCurrentIv(): string
    {
        return $this->iv;
    }

    public function requiresPadding(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->iv = $this->baseIv;
        } else {
            throw new LogicException('CBC initialization only support being'
                . ' rewound, not arbitrary seeking.'); // CBC初始化仅支持重绕，而不是任意搜索。
        }
    }

    public function update(string $cipherTextBlock): void
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1); // 初始化IV只有在第一个块加密的时候才会用到，而第N个块的加密IV则是用的N-1(N>1)个加密后的二进制数组。
    }
}