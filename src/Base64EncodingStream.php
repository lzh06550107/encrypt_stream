<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class Base64EncodingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $buffer = '';

    /**
     * @var StreamInterface
     */
    private $stream;

    public function __construct(StreamInterface $stream)
    {
        $this->stream = $stream;
    }

    public function getSize(): ?int
    {
        $unencodedSize = $this->stream->getSize();
        return $unencodedSize === null
            ? null
            : (int) ceil($unencodedSize / 3) * 4;
    }

    public function read($length): string
    {
        /**
         *
        Base64是一种用64个字符来表示任意二进制数据的方法。对二进制数据进行处理，每3个字节一组，一共是3x8=24bit，划为4组，每组正好6个bit：
         */
        $toRead = ceil($length / 4) * 3; // 就是用4个字母表示3个字节
        $this->buffer .= base64_encode($this->stream->read($toRead));

        $toReturn = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $toReturn;
    }
}