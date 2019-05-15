package com.erm.sociallogin.demo.payload;

import lombok.RequiredArgsConstructor;
import lombok.Data;
import lombok.NonNull;

@Data
@RequiredArgsConstructor
public class AuthResponse {
    @NonNull
    private String accessToken;
    private String tokenType = "Bearer";
}
