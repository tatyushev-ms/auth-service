package com.efa;

import org.springframework.core.ParameterizedTypeReference;

import java.util.Map;

public final class ParameterizedTypeReferenceInstance {
    
    private ParameterizedTypeReferenceInstance() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
    
    public static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
    };
    
    public static final ParameterizedTypeReference<Map<String, String>> STRING_STRING_MAP = new ParameterizedTypeReference<>() {
    };
    
}
