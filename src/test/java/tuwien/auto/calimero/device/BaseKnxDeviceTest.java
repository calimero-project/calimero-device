/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2017 B. Malinowsky

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
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.TPSettings;
import tuwien.auto.calimero.mgmt.Destination;
import tuwien.auto.calimero.mgmt.TransportLayer;
import tuwien.auto.calimero.process.ProcessEvent;

/**
 * @author B. Malinowsky
 */
public class BaseKnxDeviceTest extends TestCase
{
	private KnxDevice dev;
	private final IndividualAddress addr = new IndividualAddress(1, 1, 1);

	// dummy link and handlers for basic tests

	private final KNXNetworkLink link = new KNXNetworkLink() {
		/**
		 * @param settings
		 */
		@Override
		public void setKNXMedium(final KNXMediumSettings settings)
		{}

		/**
		 * @param count
		 */
		@Override
		public void setHopCount(final int count)
		{}

		/**
		 * @param dst
		 * @param p
		 * @param nsdu
		 */
		@Override
		public void sendRequestWait(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{}

		/**
		 * @param dst
		 * @param p
		 * @param nsdu
		 */
		@Override
		public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{}

		/**
		 * @param msg
		 * @param waitForCon
		 */
		@Override
		public void send(final CEMILData msg, final boolean waitForCon)
		{}

		/**
		 * @param l
		 */
		@Override
		public void removeLinkListener(final NetworkLinkListener l)
		{}

		@Override
		public boolean isOpen()
		{
			return true;
		}

		@Override
		public String getName()
		{
			return "test link";
		}

		@Override
		public KNXMediumSettings getKNXMedium()
		{
			return TPSettings.TP1;
		}

		@Override
		public int getHopCount()
		{
			return 0;
		}

		@Override
		public void close()
		{}

		/**
		 * @param l
		 */
		@Override
		public void addLinkListener(final NetworkLinkListener l)
		{}
	};

	private final ProcessCommunicationService processLogic = new ProcessCommunicationService() {
		@Override
		public ServiceResult groupReadRequest(final ProcessEvent e)
		{
			return null;
		}

		@Override
		public void groupWrite(final ProcessEvent e)
		{}

		@Override
		public void groupResponse(final ProcessEvent e)
		{}
	};

	private static class DefaultMgmtLogic implements ManagementService
	{
		@Override
		public ServiceResult writeProperty(final int objectIndex, final int propertyId, final int startIndex,
			final int elements, final byte[] data)
		{
			return null;
		}

		@Override
		public ServiceResult writeMemory(final int startAddress, final byte[] data)
		{
			return null;
		}

		@Override
		public ServiceResult writeAddressSerial(final byte[] serialNo, final IndividualAddress newAddress)
		{
			return null;
		}

		@Override
		public ServiceResult writeAddress(final IndividualAddress newAddress)
		{
			return null;
		}

		@Override
		public ServiceResult restart(final boolean masterReset, final int eraseCode, final int channel)
		{
			return null;
		}

		@Override
		public ServiceResult readPropertyDescription(final int objectIndex, final int propertyId,
			final int propertyIndex)
		{
			return null;
		}

		@Override
		public ServiceResult readProperty(final int objectIndex, final int propertyId, final int startIndex,
			final int elements)
		{
			return null;
		}

		@Override
		public ServiceResult readMemory(final int startAddress, final int bytes)
		{
			return null;
		}

		@Override
		public ServiceResult readDomainAddress()
		{
			return null;
		}

		@Override
		public ServiceResult readDomainAddress(final byte[] domain, final IndividualAddress startAddress,
			final int range)
		{
			return null;
		}

		@Override
		public ServiceResult writeDomainAddress(final byte[] domain)
		{
			return null;
		}

		@Override
		public ServiceResult readDescriptor(final int type)
		{
			return null;
		}

		@Override
		public ServiceResult readAddressSerial(final byte[] serialNo)
		{
			return null;
		}

		@Override
		public ServiceResult readAddress()
		{
			return null;
		}

		@Override
		public ServiceResult readADC(final int channel, final int consecutiveReads)
		{
			return null;
		}

		@Override
		public ServiceResult management(final int svcType, final byte[] asdu, final KNXAddress dst,
			final Destination respondTo, final TransportLayer tl)
		{
			return null;
		}

		@Override
		public ServiceResult keyWrite(final int accessLevel, final byte[] key)
		{
			return null;
		}

		@Override
		public boolean isVerifyModeEnabled()
		{
			return false;
		}

		@Override
		public ServiceResult authorize(final byte[] key)
		{
			return null;
		}
	};

	private static final ManagementService mgmtLogic = new DefaultMgmtLogic();

	/**
	 * @param name
	 */
	public BaseKnxDeviceTest(final String name)
	{
		super(name);
	}

	@Override
	protected void setUp() throws Exception
	{
		super.setUp();
		dev = new BaseKnxDevice("test", addr, link, processLogic, mgmtLogic);
	}

	@Override
	protected void tearDown() throws Exception
	{
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.BaseKnxDevice#BaseKnxDevice(String, IndividualAddress, KNXNetworkLink, ProcessCommunicationService, ManagementService)}.
	 *
	 * @throws KNXLinkClosedException
	 * @throws KNXPropertyException
	 */
	public final void testKnxDevice() throws KNXLinkClosedException, KNXPropertyException
	{
		new BaseKnxDevice("test", addr, link, null, mgmtLogic);

		try {
			new BaseKnxDevice("test", null, link, processLogic, mgmtLogic);
			fail("device address null");
		}
		catch (final NullPointerException expected) {}

		new BaseKnxDevice("test", addr, null, processLogic, mgmtLogic);

		new BaseKnxDevice("test", addr, link, processLogic, mgmtLogic);
	}

	private final class MyKnxDevice extends BaseKnxDevice
	{
		MyKnxDevice(final String name, final IndividualAddress device, final KNXNetworkLink link,
			final ProcessCommunicationService processService, final ManagementService mgmtHandler)
				throws KNXLinkClosedException, KNXPropertyException
		{
			super(name, device, link, processService, mgmtHandler);
		}

		void mySetAddress(final IndividualAddress address)
		{
			setAddress(address);
		}
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.BaseKnxDevice#setAddress(tuwien.auto.calimero.IndividualAddress)}.
	 *
	 * @throws KNXLinkClosedException
	 * @throws KNXPropertyException
	 */
	public final void testSetAddress() throws KNXLinkClosedException, KNXPropertyException
	{
		final MyKnxDevice dev2 = new MyKnxDevice("test", addr, link, processLogic, mgmtLogic);

		final IndividualAddress address = new IndividualAddress(4, 4, 4);
		dev2.mySetAddress(address);
		assertEquals(address, dev2.getAddress());

		final IndividualAddress address2 = new IndividualAddress(5, 5, 5);
		dev2.mySetAddress(address2);
		assertEquals(address2, dev2.getAddress());
	}

	/**
	 * Test method for {@link tuwien.auto.calimero.device.BaseKnxDevice#getAddress()}.
	 */
	public final void testGetAddress()
	{
		assertTrue(dev.getAddress().equals(addr));
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.BaseKnxDevice#setDeviceLink(tuwien.auto.calimero.link.KNXNetworkLink)}.
	 *
	 * @throws KNXLinkClosedException
	 */
	public final void testSetNetworkLink() throws KNXLinkClosedException
	{
		dev.setDeviceLink(link);
		assertTrue(dev.getDeviceLink() == link);
		dev.setDeviceLink(null);
		assertNull(dev.getDeviceLink());
	}
}
