#ifndef KSU_ED25519_H
#define KSU_ED25519_H

#include <linux/types.h>

/**
 * 核心签名验证函数
 * @param msg       要验证的数据指针
 * @param msg_len   数据长度
 * @param sig       64字节的Ed25519签名
 * @param pubkey    32字节的Ed25519公钥
 * @return 0 表示验证成功，-1 表示验证失败或非法
 */
int kernel_ed25519_verify(const u8 *msg, size_t msg_len,
                          const u8 *sig, const u8 *pubkey);

#endif // KSU_ED25519_H