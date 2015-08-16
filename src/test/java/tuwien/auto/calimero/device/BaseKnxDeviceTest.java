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
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.device.ios.KNXPropertyException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.TPSettings;
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
		public void setKNXMedium(final KNXMediumSettings settings)
		{}

		/**
		 * @param count
		 */
		public void setHopCount(final int count)
		{}

		/**
		 * @param dst
		 * @param p
		 * @param nsdu
		 */
		public void sendRequestWait(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{}

		/**
		 * @param dst
		 * @param p
		 * @param nsdu
		 */
		public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{}

		/**
		 * @param msg
		 * @param waitForCon
		 */
		public void send(final CEMILData msg, final boolean waitForCon)
		{}

		/**
		 * @param l
		 */
		public void removeLinkListener(final NetworkLinkListener l)
		{}

		public boolean isOpen()
		{
			return true;
		}

		public String getName()
		{
			return "test link";
		}

		public KNXMediumSettings getKNXMedium()
		{
			return TPSettings.TP1;
		}

		public int getHopCount()
		{
			return 0;
		}

		public void close()
		{}

		/**
		 * @param l
		 */
		public void addLinkListener(final NetworkLinkListener l)
		{}
	};

	private final ProcessCommunicationService processLogic = new ProcessCommunicationService() {
		public ServiceResult groupReadRequest(final ProcessEvent e)
		{
			return null;
		}

		public void groupWrite(final ProcessEvent e)
		{}

		public void groupResponse(final ProcessEvent e)
		{}
	};

	static final ManagementService mgmtLogic = new ManagementServiceTest.DefaultMgmtLogic();

	/**
	 * @param name
	 */
	public BaseKnxDeviceTest(final String name)
	{
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception
	{
		super.setUp();
		dev = new BaseKnxDevice("test", addr, link, processLogic, mgmtLogic);
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
	 * {@link tuwien.auto.calimero.device.BaseKnxDevice#KnxDevice(
	 * tuwien.auto.calimero.IndividualAddress, tuwien.auto.calimero.link.KNXNetworkLink,
	 * tuwien.auto.calimero.device.ProcessCommunicationService,
	 * tuwien.auto.calimero.device.ManagementService)}.
	 *
	 * @throws KNXLinkClosedException
	 * @throws KNXPropertyException
	 */
	public final void testKnxDevice() throws KNXLinkClosedException, KNXPropertyException
	{
		try {
			dev = new BaseKnxDevice("test", addr, link, null, mgmtLogic);
//			fail("no process handler set");
		}
		catch (final Exception e) {
			// ok
		}

		try {
			dev = new BaseKnxDevice("test", null, link, processLogic, mgmtLogic);
//			fail("no address set");
		}
		catch (final Exception e) {
			// ok
		}

		try {
			dev = new BaseKnxDevice("test", addr, null, processLogic, mgmtLogic);
			fail("no link set");
		}
		catch (final Exception e) {
			// ok
		}

		// dev = new BaseKnxDevice(addr, link, procHandler, null);
		dev = new BaseKnxDevice("test", addr, link, processLogic, mgmtLogic);
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
	 * Test method for {@link tuwien.auto.calimero.device.BaseKnxDevice
	 * setAddress(tuwien.auto.calimero.IndividualAddress)}.
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
	 * Test method for {@link tuwien.auto.calimero.device.BaseKnxDevice#setDeviceLink(
	 * tuwien.auto.calimero.link.KNXNetworkLink)}.
	 *
	 * @throws KNXLinkClosedException
	 */
	public final void testSetNetworkLink() throws KNXLinkClosedException
	{
		dev.setDeviceLink(link);
		//dev.getNetworkLink().getName().equals(link);
		dev.setDeviceLink(null);
		//assertNull(dev.getNetworkLink());
	}
}
