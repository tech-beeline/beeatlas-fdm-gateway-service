package ru.beeline.fdmgateway.consumer;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;
import ru.beeline.fdmgateway.dto.UserDropCacheMessage;
import ru.beeline.fdmgateway.service.AuthorizeService;
import ru.beeline.fdmgateway.service.UserService;

@Slf4j
@Component
public class UserDropCacheConsumer {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UserService userService;
    private final AuthorizeService authorizeService;

    public UserDropCacheConsumer(UserService userService, AuthorizeService authorizeService) {
        this.userService = userService;
        this.authorizeService = authorizeService;
    }

    @RabbitListener(queues = "${queue.user-drop-cache.name}")
    public void handle(String payload) {
        try {
            UserDropCacheMessage message = objectMapper.readValue(payload, UserDropCacheMessage.class);
            if (message == null || message.getUserLogin() == null || message.getUserLogin().trim().isEmpty()) {
                log.error("Invalid message for user_drop_cache. Required field userLogin is missing. payload={}",
                          payload);
                return;
            }

            String login = message.getUserLogin().trim();
            userService.removeFromCache(login);
            authorizeService.invalidateUser(login);
        } catch (Exception e) {
            log.error("Failed to process message from user_drop_cache. payload={}", payload, e);
        }
    }
}

