package com.olq.base.utils

import com.olq.base.BuildConfig
import com.orhanobut.logger.*


object LogUtils {

    val isLog=true

    private fun logInit() {
        if (isLog) {
            val formatStrategy: FormatStrategy = CsvFormatStrategy.newBuilder()
                .tag("custom")
                .build()
            Logger.addLogAdapter(object : DiskLogAdapter(formatStrategy) {
                override fun isLoggable(priority: Int, tag: String?): Boolean {
                    return BuildConfig.DEBUG
                }
            })
        }else {

            val formatStrategy: FormatStrategy = PrettyFormatStrategy.newBuilder()
                //显示线程信息
                .showThreadInfo(true) // (Optional) Whether to show thread info or not. Default true
                //显示多少方法行
                .methodCount(0) // (Optional) How many method line to show. Default 2
                //将内部方法调用隐藏到偏移量
                .methodOffset(7) // (Optional) Hides internal method calls up to offset. Default 5
                //打印日志策略
                //            .logStrategy(customLog) // (Optional) Changes the log strategy to print out. Default LogCat
                //日志全局标记
                .tag("Mycustomtag") // (Optional) Global tag for every log. Default PRETTY_LOGGER
                .build()
            Logger.addLogAdapter(object : AndroidLogAdapter(formatStrategy) {
                override fun isLoggable(priority: Int, tag: String?): Boolean {
                    return BuildConfig.DEBUG
                }
            })
        }
    }

    fun v( message:String,vararg args: String ){
        Logger.v(message, args)
    }
    fun d( message:String,vararg args: String ){
        Logger.d(message, args)
    }
    fun i( message:String,vararg args: String ){
        Logger.i(message, args)
    }
    fun w( message:String,vararg args: String ){
        Logger.w(message, args)
    }
    fun e( message:String,vararg args: String ){
        Logger.e(message, args)
    }

}