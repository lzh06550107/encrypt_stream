<?php
namespace Jsq\EncryptionStreams;

use LogicException;

interface CipherMethod
{
    /**
     * 返回`openssl_ *`函数可识别的标识符，例如`aes-256-cbc`或`aes-128-ctr`
     *
     * @return string
     */
    public function getOpenSslName(): string;

    /**
     * 返回应该用于加密或解密下一个块的IV
     */
    public function getCurrentIv(): string;

    /**
     * 指示与此IV一起使用的密码方法是否需要填充最后一个块以确保明文可以被块大小整除
     */
    public function requiresPadding(): bool;

    /**
     * Adjust the return of this::getCurrentIv to reflect a seek performed on
     * the encryption stream using this IV object.
     *
     * @param int $offset
     * @param int $whence
     *
     * @throws LogicException   Thrown if the requested seek is not supported by
     *                          this IV implementation. For example, a CBC IV
     *                          only supports a full rewind ($offset === 0 &&
     *                          $whence === SEEK_SET)
     */
    public function seek(int $offset, int $whence = SEEK_SET): void;

    /**
     * Take account of the last cipher text block to adjust the return of
     * this::getCurrentIv
     * 考虑最后一个密文块来调整this :: getCurrentIv的返回值
     * @param string $cipherTextBlock
     */
    public function update(string $cipherTextBlock): void;
}