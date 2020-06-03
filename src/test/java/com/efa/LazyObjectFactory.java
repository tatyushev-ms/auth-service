package com.efa;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectFactory;

/**
 * Factory that lets initialize object later.
 */
public class LazyObjectFactory<T> implements ObjectFactory<T> {
    
    private T object;
    
    @Override
    public T getObject() throws BeansException {
        if (object == null) {
            throw new IllegalStateException("Object wasn't set in factory");
        }
        return object;
    }
    
    public void setObject(T object) {
        this.object = object;
    }
    
}
