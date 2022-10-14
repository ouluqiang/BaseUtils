package com.olq.base.bean

data class WalletBean(
    val privateKey: String,
    val publicKey: String,
    val address: String,
    val mnemonics: String?="",
)