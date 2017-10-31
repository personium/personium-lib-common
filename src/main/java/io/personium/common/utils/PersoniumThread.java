/**
 * personium.io
 * Copyright 2017 FUJITSU LIMITED
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
package io.personium.common.utils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Class that executes thread using thread pool.
 * <p>
 * Please use this class in principle when executing thread.
 */
public class PersoniumThread {

    /** Thread pool. */
    private static ExecutorService threadPool;

    /**
     * Constructor.
     */
    private PersoniumThread() {
    }

    /**
     * Create thread pool.
     * @param num Thread pool num
     */
    public static void createThreadPool(int num) {
        threadPool = Executors.newFixedThreadPool(num);
    }

    /**
     * Execute the specified command.
     * If no free thread exists, it waits until it becomes executable.
     * @param command Command to execute
     */
    public static void execute(Runnable command) {
        threadPool.execute(command);
    }
}
