<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class AesGcmEncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private $aad;

    private $initializationVector;

    private $key;

    private $keySize;

    private $plaintext;

    private $tag = '';

    private $tagLength;

    public function __construct(
        StreamInterface $plaintext,
        string $key,
        string $initializationVector,
        string $aad = '', // 附加数据
        int $tagLength = 16,
        int $keySize = 256
    ) {
        $this->plaintext = $plaintext;
        $this->key = $key;
        $this->initializationVector = $initializationVector;
        $this->aad = $aad;
        $this->tagLength = $tagLength;
        $this->keySize = $keySize;
    }

    public function createStream(): StreamInterface
    {
        return Psr7\stream_for(openssl_encrypt(
            (string) $this->plaintext,
            "aes-{$this->keySize}-gcm",
            $this->key,
            OPENSSL_RAW_DATA,
            $this->initializationVector,
            $this->tag,
            $this->aad,
            $this->tagLength
        ));
    }

    public function getTag(): string
    {
        return $this->tag;
    }

    public function isWritable(): bool
    {
        return false;
    }
}