package ru.beeline.fdmgateway.filter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.turbo.TurboFilter;
import ch.qos.logback.core.spi.FilterReply;
import org.slf4j.Marker;

public class ActuatorLogFilter extends TurboFilter {

    @Override
    public FilterReply decide(Marker marker, Logger logger, Level level,
                              String format, Object[] params, Throwable t) {
        if (format != null && level == Level.DEBUG &&
                (format.contains("/actuator/health") || format.contains("/actuator/prometheus"))) {
            return FilterReply.DENY;
        }
        return FilterReply.NEUTRAL;
    }
}
