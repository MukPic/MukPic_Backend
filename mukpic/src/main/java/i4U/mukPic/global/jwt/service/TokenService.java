package i4U.mukPic.global.jwt.service;

import i4U.mukPic.global.auth.entity.Token;
import i4U.mukPic.global.auth.exception.TokenException;
import i4U.mukPic.global.auth.repository.TokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import static i4U.mukPic.global.exception.ErrorCode.TOKEN_EXPIRED;

@Slf4j
@RequiredArgsConstructor
@Service
public class TokenService {

    private final TokenRepository tokenRepository;

    public void deleteRefreshToken(String memberKey) {
        tokenRepository.deleteById(memberKey);
    }

    @Transactional
    public void saveOrUpdate(String memberKey, String refreshToken, String accessToken) {
        Token token = tokenRepository.findByAccessToken(accessToken)
                .map(o -> o.updateRefreshToken(refreshToken))
                .orElseGet(() -> new Token(memberKey, refreshToken, accessToken));

        tokenRepository.save(token);
    }

    public Token findByAccessTokenOrThrow(String accessToken) {
        return tokenRepository.findByAccessToken(accessToken)
                .orElseThrow(() -> new TokenException(TOKEN_EXPIRED));
    }

    @Transactional
    public void updateToken(String accessToken, Token token) {
        token.updateAccessToken(accessToken);
        tokenRepository.save(token);
    }
}