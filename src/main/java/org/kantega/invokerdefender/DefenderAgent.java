package org.kantega.invokerdefender;

import java.lang.instrument.Instrumentation;

/**
 *
 */
public class DefenderAgent {

    public static void premain(String options, Instrumentation instrumentation) throws Exception {
        instrumentation.addTransformer(new DefenderClassFileTransformer());
    }

    public static void agentmain(String options, Instrumentation instrumentation) throws Exception {
        instrumentation.addTransformer(new DefenderClassFileTransformer());
    }
}
