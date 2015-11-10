Invoker defender
================

invoker-defender is a Java Agent designed as a mitigation effort against deserialization attacks.

See http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ for details on this attack.

## How does it work?
 
invoker-defender makes some well known vulnerable classes effectively non-deserializable by rewriting their byte code when the class loads.
It does so by adding a readObject method (or modifying an existing readObject method) to throw an UnsupportedOperationException when a deserialization attempt is made.

## Usage

Build invoker-defender:

    mvn clean install

This builds an invoker-defender jar file in target/invoker-defender-1.0-SNAPSHOT.jar

Copy this as invoker-defender.jar to your application, and add the following parameters to your Java startup script:

    -javaagent:invoker-defender.jar

> PLEASE NOTE: In this mode, invoker-defender only does blocks a few known vulnerabilities. It does not fix the problem with deserialization attacks. It only knowns about some well known classes for which it rejects deserialization. See below how you can whitelist or completely reject any objects to be deserialized.


## Which classes are rejected?

By default, invoker-defender rejects deserialization of the following classes:

* org.apache.commons.collections.functors.InvokerTransformer
* org.apache.commons.collections4.functors.InvokerTransformer
* org.codehaus.groovy.runtime.ConvertedClosure
* com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl

You can add your own classes to this list by passing a comma-separated list of classes as a system property:

    -javaagent:invoker-defender.jar -Dinvoker.defender.custom.classes=com.example.Car,com.example.Wheel,com.example.Door


## Whitelisting mode

As always, it would be better if we could accept only classes we explicitly want to allow for deserialization. Rejecting based on a whitelist is better security than rejecting based on a blacklist.

To help build a whitelist file with legitimately serializable classes, a 'dryrun' option has been added. Together with an empty white list, this will create a list of classes which your application actually deserializes.

This can be produced by configuring the agent as follows:

    -javaagent:invoker-defender.jar -Dinvoker.defender.whitelist=empty.txt -Dinvoker.defender.dryrun=is-deserialized.txt

Where 'empty.txt' is an empty file and 'is-deserialized.txt' is a file where the names of your actually deserialized classes will be written to. 

After you are confident that all deserializable classes in your application have been recorded, you may restart your app, now reusing the recorded-as-serialized file as the whitelist:

    -javaagent:invoker-defender.jar -Dinvoker.defender.whitelist=is-deserialized.txt

## What happens when invoker-defender rejects a deserialization attempt?

An Exception will be thrown, looking something like this:

    java.lang.UnsupportedOperationException: Deserialization not allowed for class java.util.concurrent.locks.AbstractOwnableSynchronizer
    	at org.kantega.invokerdefender.DefenderClassFileTransformer.preventDeserialization(DefenderClassFileTransformer.java:119)

## Rejecting deserialization entirely

Just use an empty whitelist. Preliminary testing with a non-trivial Java application (which does not intentionally use RMI or other serialization) seems to indicate that this might work just fine. Looks like the JDK might not need serialization for any of its internal operations.


## Tracing deserialization

You might be interested not just in which classes your application deserialize, but also where in your code deserialization happens.

This can be enabled by using the 'trace' option, like the following:

     -javaagent:invoker-defender.jar -Dinvoker.defender.whitelist=empty.txt -Dinvoker.defender.dryrun=is-deserialized.txt -Dinvoker.defender.trace=deserialize-trace.txt

 This will produce a file deserialize-trace.txt looking something like this:

    Deserialization of class java.util.PriorityQueue (on Mon Nov 09 19:34:26 CET 2015)
             at org.kantega.invokerdefender.InvokerDefenderWithDryRunWhitelistAndTraceIT.deserialize
