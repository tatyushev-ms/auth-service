package com.efa;

import org.springframework.beans.factory.ObjectFactory;

import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Reflective {@link InvocationHandler} for lazy access to the current target object.
 */
public class ObjectFactoryDelegatingInvocationHandler implements InvocationHandler, Serializable {
    
    private static final long serialVersionUID = 1126698844793284449L;
    
    private final ObjectFactory<?> objectFactory;
    
    public ObjectFactoryDelegatingInvocationHandler(ObjectFactory<?> objectFactory) {
        this.objectFactory = objectFactory;
    }
    
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        switch (method.getName()) {
            case "equals":
                // Only consider equal when proxies are identical.
                return proxy == args[0];
            case "hashCode":
                // Use hashCode of proxy.
                return System.identityHashCode(proxy);
            case "toString":
                return objectFactory.toString();
        }
        try {
            return method.invoke(objectFactory.getObject(), args);
        } catch (InvocationTargetException ex) {
            throw ex.getTargetException();
        }
    }
    
}
