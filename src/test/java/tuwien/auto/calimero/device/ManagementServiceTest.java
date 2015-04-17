/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2015 B. Malinowsky

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

import junit.framework.TestCase;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.device.ios.InterfaceObject;
import tuwien.auto.calimero.device.ios.InterfaceObjectServer;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.mgmt.PropertyAccess;
import tuwien.auto.calimero.server.knxnetip.KNXnetIPServer;

/**
 * @author B. Malinowsky
 */
public class ManagementServiceTest extends TestCase
{
	private static final String knxServerConfig = "server-config.xml";
	private KNXnetIPServer server;

	public static class DefaultMgmtLogic implements ManagementService {

		@Override
		public ServiceResult writeProperty(final int objectIndex, final int propertyId,
			final int startIndex, final int elements, final byte[] data)
		{
			return null;
		}

		public ServiceResult writeMemory(final int startAddress, final byte[] data)
		{
			return null;
		}

		public ServiceResult writeAddressSerial(final byte[] serialNo,
			final IndividualAddress newAddress)
		{
			return null;
		}

		public ServiceResult writeAddress(final IndividualAddress newAddress)
		{
			return null;
		}

		public ServiceResult restart(final boolean masterReset, final int eraseCode,
			final int channel)
		{
			return null;
		}

		public ServiceResult readPropertyDescription(final int objectIndex, final int propertyId,
			final int propertyIndex)
		{
			return null;
		}

		public ServiceResult readProperty(final int objectIndex, final int propertyId,
			final int startIndex, final int elements)
		{
			return null;
		}

		public ServiceResult readMemory(final int startAddress, final int bytes)
		{
			return null;
		}

		public ServiceResult readDomainAddress()
		{
			return null;
		}

		public ServiceResult readDomainAddress(final byte[] domain,
			final IndividualAddress startAddress, final int range)
		{
			return null;
		}

		public ServiceResult writeDomainAddress(final byte[] domain)
		{
			return null;
		}

		public ServiceResult readDescriptor(final int type)
		{
			return null;
		}

		public ServiceResult readAddressSerial(final byte[] serialNo)
		{
			return null;
		}

		public ServiceResult readAddress()
		{
			return null;
		}

		public ServiceResult readADC(final int channel, final int consecutiveReads)
		{
			return null;
		}

		public ServiceResult management(final int svcType, final byte[] asdu)
		{
			return null;
		}

		public ServiceResult keyWrite(final int accessLevel, final byte[] key)
		{
			return null;
		}

		public boolean isVerifyModeEnabled()
		{
			return false;
		}

		public ServiceResult authorize(final byte[] key)
		{
			return null;
		}
	};

	final ManagementService mgmtLogic = new DefaultMgmtLogic()
	{
		KnxDevice device; // XXX init
		private final InterfaceObjectServer ios = device.getInterfaceObjectServer();
		private final byte[] memory = new byte[100];

		public ServiceResult writeProperty(final int objectIndex, final int pid,
			final int startIndex, final int elements, final byte[] data)
		{
			return null;
		}

		public ServiceResult readProperty(final int objectIndex, final int pid,
			final int elements, final int startIndex)
		{
			System.out.println("property read");
			try {
				return new ServiceResult(ios.getProperty(objectIndex, pid, startIndex, elements));
			}
			catch (final KNXException e) {
				e.printStackTrace();
			}
			return null;
		}

		public ServiceResult readMemory(final int startAddress, final int bytes)
		{
			final byte[] range = new byte[bytes];
			for (int i = 0; i < bytes; ++i)
				range[i] = memory[startAddress + i];
			return new ServiceResult(range);
		}

		public ServiceResult readDescriptor(final int type)
		{
			byte[] descriptor = null;
			if (type == 0) {
				// mask type (8 bit): Medium Type (4 bit), Firmware Type (4 bit)
				// firmware version (8 bit): version (4 bit), sub code (4 bit)
				descriptor = new byte[2];

				final byte[] mask = null;// ios.getProperty(InterfaceObject.DEVICE_OBJECT,
											// 1, PropertyAccess.PID., 1, 1);
				try {
					final byte[] firmware = ios.getProperty(InterfaceObject.DEVICE_OBJECT, 1,
							PropertyAccess.PID.FIRMWARE_REVISION, 1, 1);
				}
				catch (final KNXPropertyException e) {
					e.printStackTrace();
				}
			}
			else if (type == 2) {
				// application manufacturer (16 bit) | device type (16 bit) | version (8
				// bit) |
				// Link Mgmt Service support (2 bit) | Logical Tag (LT) base value (6 bit)
				// |
				// CI 1 (16 bit) | CI 2 (16 bit) | CI 3 (16 bit) | CI 4 (16 bit) |
				descriptor = new byte[14];
			}
			else {

			}
			return new ServiceResult(descriptor);
		}

		public ServiceResult readPropertyDescription(final int objectIndex, final int pid,
			final int propertyIndex)
		{
			try {
				return new ServiceResult(ios.getDescription(objectIndex, pid).toByteArray());
			}
			catch (final KNXException e) {
				e.printStackTrace();
			}
			return null;
		}
	};

	/**
	 * @param name
	 */
	public ManagementServiceTest(final String name)
	{
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception
	{
		super.setUp();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception
	{
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ManagementService#readProperty(int, int, int, int)}
	 * .
	 */
	public final void testOnPropertyRead()
	{
		fail("Not yet implemented"); // TODO
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ManagementService#handlePropertyWrite()}.
	 */
	public final void testOnPropertyWrite()
	{
		fail("Not yet implemented"); // TODO
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ManagementService#readPropertyDescription(int, int, int)}
	 * .
	 */
	public final void testOnPropertyDescriptionRead()
	{
		fail("Not yet implemented"); // TODO
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ManagementService#readMemory(int, int)}
	 * .
	 */
	public final void testOnMemoryRead()
	{
		fail("Not yet implemented"); // TODO
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ManagementService#writeMemory(int, byte[])}
	 * .
	 */
	public final void testOnMemoryWrite()
	{
		fail("Not yet implemented"); // TODO
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ManagementService#readDescriptor(int)}
	 * .
	 */
	public final void testOnDescriptorRead()
	{
		fail("Not yet implemented"); // TODO
	}

}
