package com.orders.user.config;

import com.orders.user.exception.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.ModelAndView;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * @author Ibney Ali
 */

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    Logger log = Logger.getLogger(RateLimitInterceptor.class.getName());

    @Value("${rate.limit.maxRequests}")
    private int maxRequests;

    @Value("${rate.limit.timeWindow}")
    private long timeWindow;

    private final ConcurrentHashMap<String, RateLimit> rateLimitMap = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (handler instanceof HandlerMethod) {
            String clientIp = request.getRemoteAddr();
            RateLimit rateLimit = rateLimitMap.computeIfAbsent(clientIp, k -> new RateLimit(maxRequests, timeWindow));
            if (!rateLimit.allowRequest()) {
                throw new RateLimitExceededException("Too many requests");
            }
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        log.info("Request handled for URL: " + request.getRequestURL());
        log.info("Response status: " + response.getStatus());
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        log.info("Request completed for URL: " + request.getRequestURL());
        if (ex != null) {
            log.severe("Exception occurred: " + ex.getMessage());
        }
    }

    private static class RateLimit {
        private final int maxRequests;
        private final long timeWindow;
        private int requestCount;
        private long windowStart;

        public RateLimit(int maxRequests, long timeWindow) {
            this.maxRequests = maxRequests;
            this.timeWindow = timeWindow;
            this.requestCount = 0;
            this.windowStart = System.currentTimeMillis();
        }

        public synchronized boolean allowRequest() {
            long now = System.currentTimeMillis();
            if (now - windowStart > timeWindow) {
                windowStart = now;
                requestCount = 0;
            }
            if (requestCount < maxRequests) {
                requestCount++;
                return true;
            }
            return false;
        }
    }
}