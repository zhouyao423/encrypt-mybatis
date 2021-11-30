package com.zy.mybatisencrypt;

import org.apache.ibatis.cache.CacheKey;
import org.apache.ibatis.executor.Executor;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.MappedStatement;
import org.apache.ibatis.plugin.*;
import org.apache.ibatis.session.ResultHandler;
import org.apache.ibatis.session.RowBounds;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.persistence.Column;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

/**
 * 敏感字段入库、出库处理
 *
 * @author zhouyao
 * @date 2021/10/27 9:25 上午
 **/
@Intercepts(
        {
                @Signature(type = Executor.class, method = "query", args = {MappedStatement.class, Object.class, RowBounds.class, ResultHandler.class}),
                @Signature(type = Executor.class, method = "update", args = {MappedStatement.class, Object.class})
        }
)
public class EncryptInterceptor implements Interceptor {

    private final String EXAMPLE_SUFFIX = "Example";


    @Override
    public Object intercept(Invocation invocation) throws Throwable {
        Object[] args = invocation.getArgs();
        MappedStatement ms = (MappedStatement) args[0];
        Object parameter = args[1];
        Class<?> argClass = parameter.getClass();
        String argClassName = argClass.getName();
        //兼容mybatis-processor
        if (needHandleExample(argClassName)){
            handleExample(args);
        }else{
            //自定义的mapper文件增删查改参数处理
            handleCustomizeMapperParams(args);
        }

        //update 方法
        if (args.length == 2 ){
            return invocation.proceed();
        }
        //兼容pagehelper
        if(args.length == 4){
            RowBounds rowBounds = (RowBounds) args[2];
            ResultHandler resultHandler = (ResultHandler) args[3];
            Executor executor = (Executor) invocation.getTarget();
            CacheKey cacheKey;
            BoundSql boundSql;
            //4 个参数时
            boundSql = ms.getBoundSql(parameter);
            cacheKey = executor.createCacheKey(ms, parameter, rowBounds, boundSql);
            List<Object> queryResult = executor.query(ms, parameter, rowBounds, resultHandler, cacheKey, boundSql);
            //处理需要解密的字段
            decryptFieldIfNeeded(queryResult);
            return queryResult;
        }

        return invocation.proceed();
    }

    /**
     * 对数据进行解密
     * @param queryResult
     */
    private void decryptFieldIfNeeded(List<Object> queryResult) throws IllegalAccessException {
        if (CollectionUtils.isEmpty(queryResult)) {
            return;
        }
        Object o1 = queryResult.get(0);
        Class<?> resultClass = o1.getClass();
        Field[] resultClassDeclaredFields = resultClass.getDeclaredFields();
        List<Field> needDecryptFieldList = new ArrayList<>();
        for (Field resultClassDeclaredField : resultClassDeclaredFields) {
            Encrypt encrypt = resultClassDeclaredField.getDeclaredAnnotation(Encrypt.class);
            if (encrypt == null){
                continue;
            }
            Class<?> type = resultClassDeclaredField.getType();
            if (!String.class.isAssignableFrom(type)){
                throw new IllegalStateException("@Encrypt should annotated on String field");
            }
            needDecryptFieldList.add(resultClassDeclaredField);
        }
        if (CollectionUtils.isEmpty(needDecryptFieldList)){
            return;
        }
        for (Field field : needDecryptFieldList) {
            field.setAccessible(true);
            for (Object o : queryResult) {
                String fieldValue = (String) field.get(o);
                if (!StringUtils.hasText(fieldValue)){
                    continue;
                }
                field.set(o,DesUtils.decrypt(fieldValue));
            }
        }
    }

    /**
     * 处理自定义mapper参数
     * @param args
     */
    private void handleCustomizeMapperParams(Object[] args) throws Exception {
        Object param = args[1];
        encryptObjectField(param);
    }

    private void encryptObjectField(Object param) throws Exception {
        Class<?> paramClass = param.getClass();
        //mybatis @param注解会处理为多参数
        if (Map.class.isAssignableFrom(paramClass)){
            Map mapParam = (Map) param;
            Set<Object> params = new HashSet<>();
            params.addAll(mapParam.values());
            for (Object o : params) {
                encryptObjectField(o);
            }
            return;
        }
        Field[] paramClassDeclaredFields = paramClass.getDeclaredFields();
        // 遍历参数的所有字段查找需要加密的字段
        for (Field paramClassDeclaredField : paramClassDeclaredFields) {
            Encrypt encrypt = paramClassDeclaredField.getDeclaredAnnotation(Encrypt.class);
            if (encrypt != null){
                //加密
                encryptField(param,paramClassDeclaredField);
            }
        }
    }

    /**
     * 给指定字段加密
     * @param targetObj
     * @param paramClassDeclaredField
     */
    private void encryptField(Object targetObj, Field paramClassDeclaredField) throws Exception {
        paramClassDeclaredField.setAccessible(true);
        Class<?> type = paramClassDeclaredField.getType();
        Object fieldValue = paramClassDeclaredField.get(targetObj);
        if (fieldValue == null){
            return;
        }

        if (Collection.class.isAssignableFrom(type)) {
            try {
                Collection<String> collection = (Collection<String>) fieldValue;
                List<String> tempList = new ArrayList<>();
                Iterator<String> iterator = collection.iterator();
                while (iterator.hasNext()) {
                    String next = iterator.next();
                    tempList.add(DesUtils.encrypt(next));
                    iterator.remove();
                }
                collection.addAll(tempList);
            }catch (Exception ex){
                //加密字段参数只支持String类型
                throw new IllegalArgumentException("Encrypted fields only support String type");
            }
        }
        else if(String.class.isAssignableFrom(type)){
            //基础数据类型直接设值
            paramClassDeclaredField.set(targetObj, DesUtils.encrypt(fieldValue.toString()));
        }
        else if (isBasicType(type)) {
            //加密字段参数只支持String类型
            throw new IllegalArgumentException("Encrypted fields only support String type");
        } else {
            //递归调用
            encryptObjectField(fieldValue);
        }
    }

    private boolean isBasicType(Class<?> clz) {
        try {
            return ((Class) clz.getField("TYPE").get(null)).isPrimitive();
        } catch (Exception e) {
            return false;
        }
    }

    //兼容processor
    private void handleExample(Object[] args) throws Exception {
        Object arg = args[1];
        Class<?> argClass = arg.getClass();
        String argClassName = argClass.getName();
        //兼容 mybatis-processor
        if (argClassName.endsWith(EXAMPLE_SUFFIX)) {
            //实体类的类名
            String modelClassName = argClassName.substring(0, argClassName.length() - 7);
            Class<?> modelClass;
            try {
                modelClass = Class.forName(modelClassName);
            }catch(ClassNotFoundException ex){
                return;
            }

            Method getCriteria = argClass.getDeclaredMethod("getCriteria");
            getCriteria.setAccessible(true);
            Object criteria = getCriteria.invoke(arg);
            Class<?> criteriaClass = criteria.getClass();
            Method getAllCriteria = criteriaClass.getDeclaredMethod("getAllCriteria");
            Set<Object> criterions = (Set<Object>) getAllCriteria.invoke(criteria);
            for (Object criterionObj : criterions) {
                Class<?> criterionClass = criterionObj.getClass();
                Method getCondition = criterionClass.getDeclaredMethod("getCondition");
                String condition = (String) getCondition.invoke(criterionObj);
                //列名
                String[] conditionParts = condition.split(" ");
                if (conditionParts.length != 2){
                    continue;
                }
                String columnName = conditionParts[0];
                //操作 >=< like
                String operateType = conditionParts[1];
                Field[] modelClassDeclaredFields = modelClass.getDeclaredFields();
                for (Field modelClassDeclaredField : modelClassDeclaredFields) {
                    Column annotation = modelClassDeclaredField.getAnnotation(Column.class);
                    if (annotation == null){
                        continue;
                    }
                    if (columnName.equalsIgnoreCase(annotation.name())){
                        Encrypt encrypt = modelClassDeclaredField.getDeclaredAnnotation(Encrypt.class);
                        if (encrypt != null) {
                            //加密字段只能用等于比较
                            if (!"=".equalsIgnoreCase(operateType)) {
                                throw new IllegalArgumentException("encrypt field only can be operate by '='");
                            }
                            Field value = criterionClass.getDeclaredField("value");
                            value.setAccessible(true);

                            List<Integer> list = new ArrayList<>();
                            list.add(1);
                            //重新设置参数
                            value.set(criterionObj,list);

                            break;
                        }
                        break;
                    }

                }
            }
        }
    }

    /**
     * 判断是否需要处理Example类型的查询
     * @param argClassName
     * @return
     */
    private boolean needHandleExample(String argClassName) {
        return argClassName.endsWith(EXAMPLE_SUFFIX);
    }

    private Object decryptIfNeeded(Invocation invocation) throws InvocationTargetException, IllegalAccessException {
        return invocation.proceed();
    }

    @Override
    public Object plugin(Object target) {
        return Plugin.wrap(target, this);
    }

    @Override
    public void setProperties(Properties properties) {
        Interceptor.super.setProperties(properties);
    }
}
