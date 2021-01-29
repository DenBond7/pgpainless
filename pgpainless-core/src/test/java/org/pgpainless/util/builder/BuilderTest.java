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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

public class BuilderTest {

    public static class ExampleParentBuilder {

        private String parentAttr;
        private String childAttr;

        public ExampleChildBuilder<ExampleParentBuilder> setParentAttr(String parentAttr) {
            this.parentAttr = parentAttr;
            return new ExampleChildBuilder<>(this,
                    new ResultCollector<ChildBuilder<ExampleParentBuilder>>() {
                        @Override
                        public void apply(ChildBuilder<ExampleParentBuilder> builder) {
                            ExampleChildBuilder<ExampleParentBuilder> child = (ExampleChildBuilder<ExampleParentBuilder>) builder;
                            ExampleParentBuilder.this.childAttr = child.childAttr;
                        }
                    });
        }

        public String getParentAttr() {
            return parentAttr;
        }

        public String getChildAttr() {
            return childAttr;
        }

        @Override
        public String toString() {
            return parentAttr + " " + childAttr;
        }
    }

    public static class ExampleChildBuilder<P> implements ChildBuilder<P> {

        private final P parent;
        private final ResultCollector<ChildBuilder<P>> resultCollector;
        private String childAttr;

        public ExampleChildBuilder(P parent, ResultCollector<ChildBuilder<P>> resultCollector) {
            this.parent = parent;
            this.resultCollector = resultCollector;
        }

        public ExampleChildBuilder<P> setChildAttr(String childAttr) {
            this.childAttr = childAttr;
            return this;
        }

        @Override
        public P getParent() {
            return parent;
        }

        @Override
        public ResultCollector<ChildBuilder<P>> getResultCollector() {
            return resultCollector;
        }
    }

    @Test
    public void test() {
        ExampleParentBuilder parent = new ExampleParentBuilder();
        ExampleChildBuilder<ExampleParentBuilder> child = parent.setParentAttr("parent");
        ExampleParentBuilder parent2 = child.setChildAttr("child").done();

        assertSame(parent, parent2);
        assertEquals("parent", parent.getParentAttr());
        assertEquals("child", parent.getChildAttr());
    }
}
