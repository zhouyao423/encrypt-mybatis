package com.zy.mybatisencrypt;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标识字段入库信息需要加密
 * @see DesUtils
 * @author zhouyao
 * @date 2021/10/27 9:22 上午
 **/
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Encrypt {
}
