package com.efa;

import org.springframework.beans.factory.ObjectFactory;

import java.lang.reflect.Proxy;

public class ProxyCreator {
    
    @SuppressWarnings("unchecked")
    public static <T> T getProxy(Class<T> type, ObjectFactory<T> factory) {
        return (T) Proxy.newProxyInstance(ProxyCreator.class.getClassLoader(), new Class<?>[]{type},
                new ObjectFactoryDelegatingInvocationHandler(factory));
    }
    
}
