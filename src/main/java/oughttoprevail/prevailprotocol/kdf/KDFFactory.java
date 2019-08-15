/*
PrevailProtocol.
Copyright (C) 2019  https://github.com/OughtToPrevail

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package oughttoprevail.prevailprotocol.kdf;

import javax.crypto.Mac;

import oughttoprevail.prevailprotocol.settings.Settings;

/**
 * A {@link KDFFactory} is responsible for creating new {@link KDF} with a {@link Mac} and {@link Settings}
 */
public interface KDFFactory
{
	/**
	 * @param mac for the {@link KDF} to use
	 * @param settings for the {@link Settings} to use
	 * @return a new {@link KDF} based on the specified mac and specified settings
	 */
	KDF newKDF(Mac mac, Settings settings);
}