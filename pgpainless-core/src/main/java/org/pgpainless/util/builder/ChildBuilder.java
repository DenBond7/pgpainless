/*
 * Copyright 2020 Paul Schaub.
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
package org.pgpainless.util.builder;

/**
 * Interface that can be implemented by builders.
 * Builders that implement this interface will be able to be "embedded" in parent builders.
 *
 * An example can be found in the BuilderTest in the test package.
 * @param <P>
 */
public interface ChildBuilder<P> {

    P getParent();

    ResultCollector<ChildBuilder<P>> getResultCollector();

    default P done() {
        if (getResultCollector() != null) {
            getResultCollector().apply(this);
        }
        return getParent();
    }
}
