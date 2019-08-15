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

/**
 * A {@link UID} is a unique identifier.
 */
public interface UID
{
	/**
	 * @return a string representation of the {@link UID}, this must always return the same value if the underlying values of the {@link UID} are
	 * the same.
	 */
	String toString();
	
	/**
	 * @param obj to compare to this object
	 * @return whether the specified obj is the same this as this and the underlying values of this and the underlying values of the specified obj equal
	 */
	boolean equals(Object obj);
	
	/**
	 * @return the hashCode of the underlying values
	 */
	int hashCode();
}