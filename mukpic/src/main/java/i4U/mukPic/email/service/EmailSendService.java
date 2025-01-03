package i4U.mukPic.email.service;

import i4U.mukPic.email.config.RedisConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;

import java.util.Objects;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class EmailSendService {

    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private RedisConfig redisConfig;

    private int authNumber;

    @Value("${spring.mail.username}")
    private String serviceName;

    public void makeRandomNum() {
        Random r = new Random();
        StringBuilder randomNumber = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            randomNumber.append(r.nextInt(10));
        }
        authNumber = Integer.parseInt(randomNumber.toString());
    }

    public void mailSend(String setFrom, String toMail, String title, String content) {
        MimeMessage message = javaMailSender.createMimeMessage();
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "utf-8");
            helper.setFrom(setFrom);
            helper.setTo(toMail);
            helper.setSubject(title);
            helper.setText(content, true);
            javaMailSender.send(message);

            // Redis에 인증 코드 저장
            redisConfig.redisTemplate().opsForValue().set(toMail, Integer.toString(authNumber), 3, TimeUnit.MINUTES);
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    public String joinEmail(String email) {
        makeRandomNum();
        String title = "회원 가입 인증 이메일입니다!";
        String content = "인증 번호는 " + authNumber + "입니다.";
        mailSend(serviceName, email, title, content);
        return Integer.toString(authNumber);
    }

    public Boolean checkAuthNum(String email, String authNum) {
        String storedCode = redisConfig.redisTemplate().opsForValue().get(email);
        return Objects.equals(storedCode, authNum);
    }
}
