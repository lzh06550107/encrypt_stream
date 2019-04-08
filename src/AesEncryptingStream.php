<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;

class AesEncryptingStream implements StreamInterface
{
    const BLOCK_SIZE = 16; // 128 bits

    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $buffer = '';

    /**
     * @var CipherMethod
     */
    private $cipherMethod;

    /**
     * @var string
     */
    private $key;

    /**
     * @var StreamInterface
     */
    private $stream;

    public function __construct(
        StreamInterface $plainText,
        string $key,
        CipherMethod $cipherMethod
    ) {
        $this->stream = $plainText;
        $this->key = $key;
        $this->cipherMethod = clone $cipherMethod;
    }

    public function getSize(): ?int
    {
        $plainTextSize = $this->stream->getSize();

        if ($this->cipherMethod->requiresPadding() && $plainTextSize !== null) {
            // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be
            // added to the plaintext to make it an even number of blocks.
            $padding = self::BLOCK_SIZE - $plainTextSize % self::BLOCK_SIZE;
            return $plainTextSize + $padding;
        }

        return $plainTextSize;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function read($length): string
    {
        if ($length > strlen($this->buffer)) { // 如果要读取的数据大于当前缓冲区的数据，则从流中读取指定长度数据然后加密这些数据并放置到缓冲区中
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );
        }

        $data = substr($this->buffer, 0, $length); // 截取指定长度的数据
        $this->buffer = substr($this->buffer, $length); // 删除缓冲区中已经读取的数据

        return $data ? $data : ''; // 返回加密的数据
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }

        if ($whence === SEEK_SET) {
            $this->buffer = '';
            $wholeBlockOffset
                = (int) ($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $this->stream->seek($wholeBlockOffset);
            $this->cipherMethod->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    // 从底层流中读取指定长度的数据，然后加密
    private function encryptBlock(int $length): string
    {
        if ($this->stream->eof()) { // 底层流读完，则直接返回
            return '';
        }

        $plainText = '';
        do {
            $plainText .= $this->stream->read($length - strlen($plainText)); // 读取指定长度的明文，因为是非阻塞，需要循环读取
        } while (strlen($plainText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA; // 不进行base64编码
        if (!$this->stream->eof()
            || $this->stream->getSize() !== $this->stream->tell()
        ) {
            $options |= OPENSSL_ZERO_PADDING; // 自动对明文进行 0 填充, 返回的结果经过 base64 编码. 但是, openssl 不推荐 0 填充的方式, 即使选择此项也不会自动进行 padding, 仍需手动 padding.
        }

        $cipherText = openssl_encrypt(
            $plainText,
            $this->cipherMethod->getOpenSslName(),
            $this->key,
            $options,
            $this->cipherMethod->getCurrentIv() // 获取当前的向量
        );

        $this->cipherMethod->update($cipherText); // 更新向量

        return $cipherText;
    }
}