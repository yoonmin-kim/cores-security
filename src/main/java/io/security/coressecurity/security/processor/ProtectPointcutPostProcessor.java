package io.security.coressecurity.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.aspectj.weaver.tools.PointcutExpression;
import org.aspectj.weaver.tools.PointcutParser;
import org.aspectj.weaver.tools.PointcutPrimitive;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.*;

public class ProtectPointcutPostProcessor implements BeanPostProcessor {
    private static final Log logger = LogFactory.getLog(io.security.coressecurity.security.processor.ProtectPointcutPostProcessor.class);
    private final Map<String, List<ConfigAttribute>> pointcutMap = new LinkedHashMap();
    private final MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource;
    private final Set<PointcutExpression> pointCutExpressions = new LinkedHashSet();
    private final PointcutParser parser;
    private final Set<String> processedBeans = new HashSet();

    public ProtectPointcutPostProcessor(MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource) {
        Assert.notNull(mapBasedMethodSecurityMetadataSource, "MapBasedMethodSecurityMetadataSource to populate is required");
        this.mapBasedMethodSecurityMetadataSource = mapBasedMethodSecurityMetadataSource;
        Set<PointcutPrimitive> supportedPrimitives = new HashSet(3);
        supportedPrimitives.add(PointcutPrimitive.EXECUTION);
        supportedPrimitives.add(PointcutPrimitive.ARGS);
        supportedPrimitives.add(PointcutPrimitive.REFERENCE);
        this.parser = PointcutParser.getPointcutParserSupportingSpecifiedPrimitivesAndUsingContextClassloaderForResolution(supportedPrimitives);
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (this.processedBeans.contains(beanName)) {
            return bean;
        } else {
            synchronized(this.processedBeans) {
                if (this.processedBeans.contains(beanName)) {
                    return bean;
                } else {
                    Method[] methods = this.getBeanMethods(bean);
                    Method[] var5 = methods;
                    int var6 = methods.length;

                    for(int var7 = 0; var7 < var6; ++var7) {
                        Method method = var5[var7];
                        Iterator var9 = this.pointCutExpressions.iterator();

                        while(var9.hasNext()) {
                            PointcutExpression expression = (PointcutExpression)var9.next();
                            if (this.attemptMatch(bean.getClass(), method, expression, beanName)) {
                                break;
                            }
                        }
                    }

                    this.processedBeans.add(beanName);
                    return bean;
                }
            }
        }
    }

    private Method[] getBeanMethods(Object bean) {
        try {
            return bean.getClass().getMethods();
        } catch (Exception var3) {
            throw new IllegalStateException(var3.getMessage());
        }
    }

    /**
     * 설정클래스에서 람다 형식으로 선언된 빈이 존재할 경우 에러가 발생하여 스프링 빈과 동일한 클래스를 생성하여 약간 수정함
     * 아직 AspectJ 라이브러리에서 Fix 하지 못한 것으로 판단되지만 다른 원인이 존재하는지 계속 살펴보도록 함
     */
    private boolean attemptMatch(Class<?> targetClass, Method method, PointcutExpression expression, String beanName) {
        boolean matches;
        try {
            matches = expression.matchesMethodExecution(method).alwaysMatches();
            if (matches) {
                List<ConfigAttribute> attr = pointcutMap.get(expression.getPointcutExpression());

                if (logger.isDebugEnabled()) {
                    logger.debug("AspectJ pointcut expression '"
                            + expression.getPointcutExpression() + "' matches target class '"
                            + targetClass.getName() + "' (bean ID '" + beanName
                            + "') for method '" + method
                            + "'; registering security configuration attribute '" + attr
                            + "'");
                }
                mapBasedMethodSecurityMetadataSource.addSecureMethod(targetClass, method, attr);
            }
            return matches;

        } catch (Exception e) {
            matches = false;
        }
        return matches;
    }

    public void setPointcutMap(Map<String, List<ConfigAttribute>> map) {
        Assert.notEmpty(map, "configAttributes cannot be empty");
        Iterator var2 = map.keySet().iterator();

        while(var2.hasNext()) {
            String expression = (String)var2.next();
            List<ConfigAttribute> value = (List)map.get(expression);
            this.addPointcut(expression, value);
        }

    }

    private void addPointcut(String pointcutExpression, List<ConfigAttribute> definition) {
        Assert.hasText(pointcutExpression, "An AspectJ pointcut expression is required");
        Assert.notNull(definition, "A List of ConfigAttributes is required");
        pointcutExpression = this.replaceBooleanOperators(pointcutExpression);
        this.pointcutMap.put(pointcutExpression, definition);
        this.pointCutExpressions.add(this.parser.parsePointcutExpression(pointcutExpression));
        if (logger.isDebugEnabled()) {
            logger.debug("AspectJ pointcut expression '" + pointcutExpression + "' registered for security configuration attribute '" + definition + "'");
        }

    }

    private String replaceBooleanOperators(String pcExpr) {
        pcExpr = StringUtils.replace(pcExpr, " and ", " && ");
        pcExpr = StringUtils.replace(pcExpr, " or ", " || ");
        pcExpr = StringUtils.replace(pcExpr, " not ", " ! ");
        return pcExpr;
    }
}
