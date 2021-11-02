package org.google.RecaptchaEnterprise;

import static org.google.RecaptchaEnterprise.RecaptchaHelper.RECAPTCHA_SCORE;

import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.validators.FloatValidator;


/**
 * A node that checks the Recaptcha Enterprise score.
 */
@Node.Metadata(outcomeProvider = RecaptchaEnterpriseScoreNode.RecaptchaEnterpriseScoreNodeOutcomeProvider.class,
        configClass = RecaptchaEnterpriseScoreNode.Config.class)
public class RecaptchaEnterpriseScoreNode implements Node {

    private static final String BUNDLE = RecaptchaEnterpriseScoreNode.class.getName();
    private final Config config;
    private final Logger logger = LoggerFactory.getLogger(RecaptchaEnterpriseScoreNode.class);


    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Policy Score Threshold
         */
        @Attribute(order = 100, validators = {FloatValidator.class})
        default String scoreThreshold() { return "0.0"; }

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public RecaptchaEnterpriseScoreNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {

        if (logger.isDebugEnabled()) {
            logger.debug("Evaluating if score {} is greater than or equal to {}", context.sharedState.get(RECAPTCHA_SCORE), config.scoreThreshold());
        }

        if (context.sharedState.get(RECAPTCHA_SCORE).asDouble() >= Double.parseDouble(config.scoreThreshold())) {
            return Action.goTo(RecaptchaEnterpriseScoreNodeOutcome.GREATER_THAN_OR_EQUAL.name()).build();
        }
        return Action.goTo(RecaptchaEnterpriseScoreNodeOutcome.LESS_THAN.name()).build();

    }


    /**
     * The possible outcomes for the Recaptcha Score Node.
     */
    private enum RecaptchaEnterpriseScoreNodeOutcome {
        GREATER_THAN_OR_EQUAL,
        LESS_THAN
    }


    /**
     * Defines the possible outcomes from this Recaptcha Score Node
     */
    public static class RecaptchaEnterpriseScoreNodeOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                                                                       RecaptchaEnterpriseScoreNode.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(RecaptchaEnterpriseScoreNodeOutcome.GREATER_THAN_OR_EQUAL.name(),
                                bundle.getString("greaterThanOrEqualOutcome")),
                    new Outcome(RecaptchaEnterpriseScoreNodeOutcome.LESS_THAN.name(),
                                bundle.getString("lessThanOutcome")));
        }
    }
}
