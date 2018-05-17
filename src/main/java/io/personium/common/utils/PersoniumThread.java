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
import java.util.concurrent.TimeUnit;

/**
 * Class that executes thread using thread pool.
 * <p>
 * Please use this class in principle when executing thread.
 */
public enum PersoniumThread {

    /** For cell export, import uses. */
    CELL_IO,
    /** For box import uses. */
    BOX_IO,
    /** For miscellaneous uses. */
    MISC;

    /** Thread pool. */
    private ExecutorService threadPool;

    /**
     * Constructor.
     */
    private PersoniumThread() {
    }

    /**
     * Execute the specified command.
     * If no free thread exists, it waits until it becomes executable.
     * @param command Command to execute
     */
    public void execute(Runnable command) {
        threadPool.execute(command);
    }

    /**
     * Create thread pool.
     * @param cellIONum Thread pool num for cell io
     * @param boxIONum Thread pool num for box io
     * @param miscNum Thread pool num for misc
     */
    public static void start(int cellIONum, int boxIONum, int miscNum) {
        CELL_IO.createThreadPool(cellIONum);
        BOX_IO.createThreadPool(boxIONum);
        MISC.createThreadPool(miscNum);
    }

    /**
     * Shutdown thread pool.
     * @param timeout the maximum seconds to wait
     */
    public static void stop(long timeout) {
        CELL_IO.shutdown(timeout);
        BOX_IO.shutdown(timeout);
        MISC.shutdown(timeout);
    }

    /**
     * Create thread pool.
     * @param num Thread pool num
     */
    private void createThreadPool(int num) {
        threadPool = Executors.newFixedThreadPool(num);
    }

    /**
     * Shutdown thread pool.
     * @param timeout the maximum seconds to wait
     */
    private void shutdown(long timeout) {
        if (threadPool != null) {
            threadPool.shutdown();
            try {
                if (!threadPool.awaitTermination(timeout, TimeUnit.SECONDS)) {
                    threadPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                threadPool.shutdownNow();
            }
            threadPool = null;
        }
    }
}
