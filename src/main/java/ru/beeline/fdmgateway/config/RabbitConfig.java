package ru.beeline.fdmgateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.rabbit.connection.CachingConnectionFactory;
import org.springframework.amqp.rabbit.connection.Connection;
import org.springframework.amqp.rabbit.connection.ConnectionListener;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.amqp.support.converter.SimpleMessageConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import ru.beeline.fdmgateway.client.AuthSSOClient;

@Configuration
public class RabbitConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(RabbitConfig.class);

    @Value("${app.ambassador-auth:true}")
    private Boolean ambassadorAuth;

    @Value("${spring.rabbitmq.username:}")
    private String userName;

    @Value("${spring.rabbitmq.password:}")
    private String password;

    @Value("${spring.rabbitmq.virtual-host:/}")
    private String virtualHost;

    @Value("${spring.rabbitmq.host:localhost}")
    private String connectFactoryName;

    @Value("${queue.user-drop-cache.name:user_drop_cache}")
    private String userDropCacheQueueName;

    @Autowired
    private AuthSSOClient authSSOClient;

    @Bean
    public Queue userDropCacheQueue() {
        return new Queue(userDropCacheQueueName, true);
    }

    @Bean
    public CachingConnectionFactory connectionFactory() {
        return ambassadorAuth ? createConnectionFactoryWithToken() : createConnectionFactoryWithPass();
    }

    private CachingConnectionFactory createConnectionFactoryWithPass() {
        CachingConnectionFactory cachingConnectionFactory = new CachingConnectionFactory(connectFactoryName);
        cachingConnectionFactory.setUsername(userName);
        cachingConnectionFactory.setPassword(password);
        cachingConnectionFactory.setVirtualHost(virtualHost);
        return cachingConnectionFactory;
    }

    private CachingConnectionFactory createConnectionFactoryWithToken() {
        CachingConnectionFactory factory = new CachingConnectionFactory(connectFactoryName);
        factory.setUsername("");
        factory.setPassword(authSSOClient.getToken());
        factory.setVirtualHost(virtualHost);

        factory.addConnectionListener(new ConnectionListener() {
            @Override
            public void onCreate(Connection connection) {
                LOGGER.info("create connection and update token");
                factory.setPassword(authSSOClient.getToken());
            }

            @Override
            public void onClose(Connection connection) {
            }
        });
        return factory;
    }

    @Bean
    MessageConverter messageConverter() {
        return new SimpleMessageConverter();
    }

    @Bean
    RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(messageConverter());
        return rabbitTemplate;
    }
}

