package org.zerock.api01.util;


import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTests {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerate(){

        Map<String, Object> claimMap = Map.of("mid", "ABCDE");

        String jwtStr = jwtUtil.generateToken(claimMap,1);

        log.info(jwtStr);
    }

    @Test
    public void testValidate(){
        //첫째 테스트에서 유효기간 1분으로 설정한 JWT
        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3MDM4Mjg2NTEsIm1pZCI6IkFCQ0RFIiwiaWF0IjoxNzAzODI4NTkxfQ.S4d__ZEEaxWbU8DREsxa4aekwMjerZ5-rcLNtesSVto";

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);
        //io.jsonwebtoken.ExpiredJwtException: JWT expired at 2023-12-29T14:44:11Z. Current time: 2023-12-29T15:08:37Z
        //1분으로 설정했었으므로, exp 부분에서 검증 통과 못했으므로 예외 발생

        log.info(claim);
    }

    @Test
    public void testAll(){
        String jwtStr = jwtUtil.generateToken(Map.of("mid","AAAA","email","aaaa@bbb.com"),1);
        //generateToken은 Map객체를 받아 jwt로 변환하므로.
        log.info(jwtStr);

        Map<String,Object> claim = jwtUtil.validateToken(jwtStr);

        log.info("MID : " + claim.get("mid"));

        log.info("EMAIL : " + claim.get("email"));

    }
}
