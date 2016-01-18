/*
 * Copyright 2015 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kantega.notsoserial;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

/**
 *
 */
public class Options {


    private static Options instance;

    private final NotSoSerial notSoSerial;
    private final List<NotSoSerialTransformer> notSoSerialTransformers;


    public Options(ClassLoader classLoader) {

        NotSoSerial notSoSerial = null;

        ServiceLoader<NotSoSerial> notSoSerials = ServiceLoader.load(NotSoSerial.class, classLoader);
        Iterator<NotSoSerial> iterator = notSoSerials.iterator();

        if(iterator.hasNext()) {
            notSoSerial = iterator.next();
        }
        if(iterator.hasNext()) {
            throw new IllegalStateException("Classpath has more than one implementation of " + NotSoSerial.class.getName());
        }

        if(notSoSerial == null) {
            notSoSerial = new DefaultNotSoSerial();
        }

        this.notSoSerial = notSoSerial;

        this.notSoSerialTransformers = new ArrayList<NotSoSerialTransformer>();

        for(NotSoSerialTransformer trans : ServiceLoader.load(NotSoSerialTransformer.class, classLoader)) {
            notSoSerialTransformers.add(trans);
        }
    }

    public static Options getInstance() {
        return instance;
    }

    public NotSoSerial getNotSoSerial() {
        return notSoSerial;
    }

    public static Options makeInstance(ClassLoader classLoader) {
        return instance = new Options(classLoader);
    }

    public List<NotSoSerialTransformer> getNotSoSerialTransformers() {
        return notSoSerialTransformers;
    }
}
