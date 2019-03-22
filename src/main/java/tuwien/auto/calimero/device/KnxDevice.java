/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2019 B. Malinowsky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Linking this library statically or dynamically with other modules is
    making a combined work based on this library. Thus, the terms and
    conditions of the GNU General Public License cover the whole
    combination.

    As a special exception, the copyright holders of this library give you
    permission to link this library with independent modules to produce an
    executable, regardless of the license terms of these independent
    modules, and to copy and distribute the resulting executable under terms
    of your choice, provided that you also meet, for each linked independent
    module, the terms and conditions of the license of that module. An
    independent module is a module which is not derived from or based on
    this library. If you modify this library, you may extend this exception
    to your version of the library, but you are not obligated to do so. If
    you do not wish to do so, delete this exception statement from your
    version.
*/

package tuwien.auto.calimero.device;

import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;

/**
 * A Calimero KNX device.
 *
 * @author B. Malinowsky
 */
public interface KnxDevice
{
	/**
	 * Returns the currently assigned device individual address or default individual address of this device.
	 *
	 * @return the currently set device address
	 */
	IndividualAddress getAddress();

	/**
	 * Sets the communication link used by this device; assigns the device address from the link's
	 * medium settings, if that individual address denotes a device address.
	 *
	 * @param link the network link
	 * @throws KNXLinkClosedException if the supplied link is closed
	 */
	void setDeviceLink(KNXNetworkLink link) throws KNXLinkClosedException;

	/**
	 * Returns the KNX network link this device is attached to.
	 *
	 * @return the link
	 */
	KNXNetworkLink getDeviceLink();

	/**
	 * Returns the Interface Object Server (IOS) used for KNX property services and device information.
	 *
	 * @return the interface object server
	 */
	InterfaceObjectServer getInterfaceObjectServer();
}
