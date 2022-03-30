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
package io.personium.common.auth.token;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Model of the Role in Personium.
 */
public class Role {
    /**
     * Edm EntityType Name.
     */
    public static final String EDM_TYPE_NAME = "Role";

    /**
     * Role Name.
     */
    private String name;
    /**
     * Name of the box, if any, which this box is bound to.
     */
    private String boxName;
    /**
     * Schema Uri of the box, if any, which this box is bound to.
     */
    private String boxSchema;
    /**
     * Cell URL of the role resource corresponding to this role.
     */
    private String baseUrl;

    /**
     * Constructor.
     * @param url Role Resource URL
     * @throws MalformedURLException if URL is malformed
     * @deprecated
     */
    public Role(URL url) throws MalformedURLException {
        // Role Resource URL looks like this.
        // https://localhost:8080/dc1-core/testcell1/__role/box1/rolename
        Pattern pattern = Pattern.compile("(.+/)__role/([^/]+)/(.+)");
        Matcher matcher = pattern.matcher(url.toString());
        if (!matcher.find()) {
            throw new MalformedURLException("No match found.");
        }
        this.name = matcher.group(INDEX_ROLE_URL_ROLE_NAME);
        this.boxName = matcher.group(INDEX_ROLE_URL_BOX_NAME);
        this.baseUrl = matcher.group(INDEX_ROLE_URL_BASE);
    }
    /**
     * create a Role from role class url.
     * @param roleClassUrl role class url
     * @return Role object
     * @throws MalformedURLException when the given url is invalid
     */
    public static Role createFromRoleClassUrl(String roleClassUrl) throws MalformedURLException {
        Pattern pattern = Pattern.compile("(.+/)__role/([^/]+)/(.+)");
        Matcher matcher = pattern.matcher(roleClassUrl);
        if (!matcher.find()) {
            throw new MalformedURLException("This is not a role class url. [" + roleClassUrl + "]");
        }
        String name = matcher.group(INDEX_ROLE_URL_ROLE_NAME);
        String boxName = matcher.group(INDEX_ROLE_URL_BOX_NAME);
        String baseUrl = matcher.group(INDEX_ROLE_URL_BASE);
        if (!MAIN_BOX_NAME.equals(boxName)) {
            throw new MalformedURLException("This is not a role class url. [" + roleClassUrl + "]");
        }
        return new Role(name, boxName, baseUrl, baseUrl);
    }
    /**
     * create a Role from role instance url.
     * note that the box schema information can not be automatically poplulated in this method.
     * @param roleInstanceUrl role instance url
     * @return Role object
     * @throws MalformedURLException when the given url is invalid
     */
    public static Role createFromRoleInstanceUrl(String roleInstanceUrl) throws MalformedURLException {
        Pattern pattern = Pattern.compile("(.+/)__role/([^/]+)/(.+)");
        Matcher matcher = pattern.matcher(roleInstanceUrl);
        if (!matcher.find()) {
            throw new MalformedURLException("This is not a role instance url. [" + roleInstanceUrl + "]");
        }
        String name = matcher.group(INDEX_ROLE_URL_ROLE_NAME);
        String boxName = matcher.group(INDEX_ROLE_URL_BOX_NAME);
        String baseUrl = matcher.group(INDEX_ROLE_URL_BASE);
        return new Role(name, boxName, null, baseUrl);
    }

    /**
     * Constructor.
     * @param name Role Name.
     * @param boxName Name of the box this role is bound to.
     * @param boxSchema Schema URI of the box  this role is bound to.
     * @param baseUrl Cell URL of this role
     */
    public Role(final String name, final String boxName, final String boxSchema, final String baseUrl) {
        this.name = name;
        this.boxName = boxName;
        this.boxSchema = boxSchema;
        this.baseUrl = baseUrl;
    }

    /**
     * Constructor for test.
     * @deprecated
     * @param name role name.
     */
    public Role(final String name) {
        this(name, null, null, null);
    }
    @Override
    public boolean equals(Object obj) {
        boolean ret = obj instanceof Role;
        Role r = (Role) obj;
        ret &= Objects.equals(this.name, r.name);
        ret &= Objects.equals(this.boxSchema, r.boxSchema);
        ret &= Objects.equals(this.boxName, r.boxName);
        ret &= Objects.equals(this.baseUrl, r.baseUrl);
        return ret;
    }

    /**
     * Returns Role instance URL for this role.
     * @deprecated
     * @param url base URL of role resource
     * @return Role instance URL.
     */
    public String schemeCreateUrl(String url) {
        // Roleに紐付くBox判断
        String boxName2 = null;
        if (this.boxName != null) {
            boxName2 = this.boxName;
        } else {
            // If not bound to any box, then use main box name.
            boxName2 = MAIN_BOX_NAME;
        }
        String url3 = createBaseUrl(url);
        return String.format(ROLE_RESOURCE_FORMAT, url3, boxName2, this.name);
    }

    /**
     * Returns Role class URL.
     * @deprecated
     * @param url base URL of role resource
     * @return String Role resource URL
     */
    public String schemeCreateUrlForTranceCellToken(String url) {
        return this.toRoleClassURL();
    }
    /**
     * Returns Role class URL.
     * @return String Role class URL
     */
    public String toRoleClassURL() {
        if (this.boxSchema != null) {
            return String.format(ROLE_RESOURCE_FORMAT, this.boxSchema, MAIN_BOX_NAME, this.name);
        }
        if (this.baseUrl == null) {
            throw new RuntimeException("Cannot create role class url since baseUrl is null for boxName = main");
        }
        return String.format(ROLE_RESOURCE_FORMAT, this.baseUrl, MAIN_BOX_NAME, this.name);
    }
    /**
     * Returns Role Instance URL.
     * @return String Role instance URL
     */
    public String toRoleInstanceURL() {
        if (this.baseUrl == null) {
            throw new RuntimeException("Cannot create role instance url without baseUrl.");
        }
        if (this.boxName == null) {
            if (this.boxSchema != null) {
                throw new RuntimeException("Illegal State. box schema is given but box name is null ");
            }
            return String.format(ROLE_RESOURCE_FORMAT, this.baseUrl, MAIN_BOX_NAME, this.name);
        }
        if (this.boxSchema == null) {
            // Box name is given but schema is null
            return String.format(ROLE_RESOURCE_FORMAT, this.baseUrl, this.boxName, this.name);
        }
        return String.format(ROLE_RESOURCE_FORMAT, this.baseUrl, this.boxName, this.name);
    }
    /**
     */
    private String createBaseUrl(String url) {
        String url2 = null;
        if (this.boxName != null && this.boxSchema != null && !"null".equals(this.boxSchema)) {
            // BOXに紐付いている場合BOXに設定されているスキーマURLをBaseURLに使う
            // なお、BOXにスキーマURLが設定されていない場合は設定ミスの可能性があるので紐付いていないとみなす。
            url2 = this.boxSchema;
        } else {
            // BOXに紐付いていない場合ISSUERをBaseURLに使う
            url2 = url;
        }
        // 連結でスラッシュつけてるので、URLの最後がスラッシュだったら消す。
        String url3 = url2.replaceFirst("/$", "");
        return url3;
    }

    /**
     * @deprecated
     * ローカル用ロールリソースのURLを返す.
     * @param url ロールリソースのベースURL
     * @return String ロールリソースのURL
     */
    public String localCreateUrl(String url) {
        // ロールに紐付くBox判断
        String boxName2 = null;
        if (this.boxName != null) {
            boxName2 = this.boxName;
        } else {
            // 紐付かない場合、デフォルトボックス名を使用する
            boxName2 = MAIN_BOX_NAME;
        }
        // 連結でスラッシュつけてるので、URLの最後がスラッシュだったら消す。
        String url3 = url.replaceFirst("/$", "");
        return String.format(ROLE_RESOURCE_FORMAT, url3, boxName2, this.name);
    }

    /**
     * @deprecated
     * ロールリソースのURLを返す.
     * @return String ロールリソースのURL
     */
    public String createUrl() {
        return schemeCreateUrl(this.baseUrl);
    }

    /**
     * gets the name of this role.
     * @return Role Name
     */
    public String getName() {
        return name;
    }

    /**
     * gets the name of the box this role is bound to.
     * @return Name of the box this role is bound to.
     */
    public String getBoxName() {
        return boxName;
    }

    /**
     * gets the schema uri of the box this role is bound to.
     * @return schema uri of the box this role is bound to.
     */
    public String getBoxSchema() {
        return boxSchema;
    }

    /**
     * gets the Base Url of the role.
     * @return base Url of the role.
     */
    public String getBaseUrl() {
        return baseUrl;
    }


    private static final int INDEX_ROLE_URL_BASE = 1;
    private static final int INDEX_ROLE_URL_BOX_NAME = 2;
    private static final int INDEX_ROLE_URL_ROLE_NAME = 3;
    /**
     * Role Resource URL format.
     */
    public static final String ROLE_RESOURCE_FORMAT = "%s__role/%s/%s";
    /**
     * Main Box Name.
     */
    public static final String MAIN_BOX_NAME = "__";
}
