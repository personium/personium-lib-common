/**
 * Personium
 * Copyright 2014-2022 Personium Project Authors
 * - FUJITSU LIMITED
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
package io.personium.common.file;

/**
 * Exception thrown upon File Data input / output.
 */
public class FileDataNotFoundException extends FileDataAccessException {

    /**
     * Default Serial Version ID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Constructor.
     * @param msg Message
     * @param cause Causing Throwable
     */
    public FileDataNotFoundException(String msg, Throwable cause) {
        super(msg, cause);
    }

    /**
     * Constructor.
     * @param msg Message
     */
    public FileDataNotFoundException(String msg) {
        super(msg);
    }
}
