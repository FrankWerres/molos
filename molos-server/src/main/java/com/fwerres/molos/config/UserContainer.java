/*
 * Copyright 2023 Frank Werres (https://github.com/FrankWerres/molos)
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
package com.fwerres.molos.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class UserContainer {

	private List<UserConfig> users;

	public List<UserConfig> getUsers() {
		return users;
		
	}

	public void setUsers(Collection<UserConfig> users) {
		this.users = new ArrayList<>(users.size());
		this.users.addAll(users);
	}
}
