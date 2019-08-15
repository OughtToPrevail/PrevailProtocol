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
package oughttoprevail.prevailprotocol.uid;

import oughttoprevail.prevailprotocol.storage.fields.SerDes;

/**
 * A factory for serializing, deserializing and generating {@link UID}.
 */
public interface UIDFactory extends SerDes<UID>
{
	/**
	 * Generates and returns a new {@link UID}.
	 * This {@link UID} must be unique!
	 *
	 * @return a new unique {@link UID}
	 */
	UID generateUID();
}