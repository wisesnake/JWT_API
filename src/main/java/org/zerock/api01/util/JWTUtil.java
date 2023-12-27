package org.zerock.api01.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Date;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {

    @Value("${org.zerock.jwt.secret}")
    //lombok의 value가 아님을 주의, properties 문서나 환경 변수등의 값을 필드의 value로 초기화함을 뜻하는 어노테이션
    private String key;

    public String generateToken(Map<String, Object> valueMap, int days){

        log.info("generateKey...." + key);


        // JWT 헤더 설정
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");   // 토큰의 타입
        headers.put("alg", "HS256"); // 토큰의 알고리즘

        // JWT 페이로드 설정
        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);   // 전달받은 데이터(valueMap)를 페이로드에 추가

        // 테스트용이므로 유효기간 짧게 설정
        int time = (60 * 24) * days; // 유효기간(분) 보통 60*24 (1일) 단위로 설정하게 됨

        // JWT 토큰 생성
        String jwtStr = Jwts.builder()
                .setHeader(headers)  // 헤더 설정
                .setClaims(payloads) // 페이로드 설정
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant())) // 토큰 발급 시간 설정
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant())) // 토큰 만료 시간 설정
                .signWith(SignatureAlgorithm.HS256, key.getBytes()) // 서명 알고리즘 및 비밀키 설정
                .compact(); // 최종적으로 JWT 문자열 생성

        //이를 기반으로, jwt의 3가지 클레임(헤더,페이로드,서명)을 생성하여 반환하는 메소드.
        //header : typ, alg
        // -> 서버로 전송되는 토큰의 메타데이터를 포함하여, 주로 토큰의 타입과 서명 알고리즘을 지정함. 서버측에서 검증하기 위해 필요한 정보인
        //    토큰의 구조와 해석 방법을 정의하는데 사용됨
        //payload : iss(발급자), sub(제목), exp(만료기간), iat(발급시간), aud(대상자), nbf(활성시간), jti(고유식별자)
        // -> 토큰에 포함된 클레임, 즉 정보를 담고있음, 서버에서 비즈니스로직을 수행하기 위한 데이터를 담고있음
        //signature : (header+payload)의 인코딩값을 해싱 + 비밀키
        // -> 토큰의 무결성을 검증하기 위한 비밀 키로 생성된 값, 서버측에서 토큰이 클라이언트에서 발급된게 맞는지, 변조되지 않았는지 확인하는데 사용

        // 생성된 JWT 문자열 반환
        return jwtStr;
    }

    public Map<String, Object> validateToken(String token)throws JwtException {
        Map<String, Object> claim = null;

        claim = Jwts.parser() // 검증
                .setSigningKey(key.getBytes()) // Set Key(application.properties에 설정해둔 비밀키)
                .parseClaimsJws(token) // 파싱 및 검증, 실패 시 에러
                .getBody(); // 올바르게 검증되었을 때만 JWT의 내용을 claim객체로 반환함.

        return claim;
    }

}
