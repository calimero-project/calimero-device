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

import java.util.Collections;
import java.util.EventListener;
import java.util.LinkedList;
import java.util.List;

import junit.framework.TestCase;
import tuwien.auto.calimero.DataUnitBuilder;
import tuwien.auto.calimero.FrameEvent;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXAddress;
import tuwien.auto.calimero.Priority;
import tuwien.auto.calimero.cemi.CEMIFactory;
import tuwien.auto.calimero.cemi.CEMILData;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.internal.EventListeners;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.NetworkLinkListener;
import tuwien.auto.calimero.link.medium.KNXMediumSettings;
import tuwien.auto.calimero.link.medium.TPSettings;
import tuwien.auto.calimero.process.ProcessEvent;
import tuwien.auto.calimero.server.KNXPropertyException;

/**
 * @author B. Malinowsky
 */
public class BaseKnxDeviceTest extends TestCase
{
	private KnxDevice dev;
	private final IndividualAddress addr = new IndividualAddress(1, 1, 1);

	// dummy link and handlers for basic tests

	private final KNXNetworkLink link = new KNXNetworkLink()
	{
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
		public void sendRequestWait(final KNXAddress dst, final Priority p,
			final byte[] nsdu)
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
			return null;
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

	private final ProcessCommunicationService processLogic = new ProcessCommunicationService()
	{
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
		dev = new BaseKnxDevice(addr, link, processLogic, mgmtLogic);
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
			dev = new BaseKnxDevice(addr, link, null, mgmtLogic);
			fail("no process handler set");
		}
		catch (final Exception e) {
			// ok
		}

		try {
			dev = new BaseKnxDevice(null, link, processLogic, mgmtLogic);
			fail("no address set");
		}
		catch (final Exception e) {
			// ok
		}

		try {
			dev = new BaseKnxDevice(addr, null, processLogic, mgmtLogic);
			fail("no link set");
		}
		catch (final Exception e) {
			// ok
		}

		// dev = new BaseKnxDevice(addr, link, procHandler, null);
		dev = new BaseKnxDevice(addr, link, processLogic, mgmtLogic);
	}

	private final class MyKnxDevice extends BaseKnxDevice
	{
		MyKnxDevice(final IndividualAddress device, final KNXNetworkLink link,
			final ProcessCommunicationService processService,
			final ManagementService mgmtHandler) throws KNXLinkClosedException, KNXPropertyException
		{
			super(device, link, processService, mgmtHandler);
		}

		void mySetAddress(final IndividualAddress address)
		{
			setAddress(address);
		}
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.BaseKnxDevice
	 * setAddress(tuwien.auto.calimero.IndividualAddress)}.
	 *
	 * @throws KNXLinkClosedException
	 * @throws KNXPropertyException
	 */
	public final void testSetAddress() throws KNXLinkClosedException, KNXPropertyException
	{
		final MyKnxDevice dev2 = new MyKnxDevice(addr, link, processLogic, mgmtLogic);

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

	// XXX message processing and threading test

	private static int instance = 0;

	// A link implementation used for virtual KNX networks.
	// In such network, only the library network buffer is used to emulate
	// a KNX subnetwork without existing link to a real KNX installation.
	private class VirtualLink implements KNXNetworkLink
	{
		private final EventListeners listeners = new EventListeners();
		private final EventListeners otherListeners = new EventListeners();
		private volatile boolean closed;
		private volatile int hopCount = 6;
		private KNXMediumSettings ms = TPSettings.TP1;

		// not private since access is required from subclass to its fields
		/*private*/final List list = Collections.synchronizedList(new LinkedList());
		/*private*/final Thread dispatcher;

		public VirtualLink()
		{
			dispatcher = new Thread()
			{
				{
					setName("VirtualLink Dispatcher " + instance++);
				}

				public void run()
				{
					try {
						while (true) {
							// XXX if we spuriously wake up, remove will throw if no entry
							if (list.size() > 0) {
								final Object[] item = (Object[]) list.remove(0);
								VirtualLink.this.mySend((CEMILData) item[0],
									(EventListeners) item[1], (EventListeners) item[2]);
							}
							synchronized (this) {
								wait();
							}
						}
					}
					catch (final InterruptedException e) {
						e.printStackTrace();
					}
				};
			};
			dispatcher.start();
		}

		KNXNetworkLink getDeviceLink()
		{
			return new VirtualLink()
			{
				/*
				 * (non-Javadoc)
				 * @see
				 * Launcher.VirtualLink#addLinkListener(tuwien.auto.calimero.link.
				 * NetworkLinkListener)
				 */
				public void addLinkListener(final NetworkLinkListener l)
				{
					otherListeners.add(l);
				}

				/*
				 * (non-Javadoc)
				 * @see
				 * Launcher.VirtualLink#removeLinkListener(tuwien.auto.calimero.link
				 * .NetworkLinkListener)
				 */
				public void removeLinkListener(final NetworkLinkListener l)
				{
					otherListeners.remove(l);
				}

				/*
				 * (non-Javadoc)
				 * @see Launcher.VirtualLink#send(tuwien.auto.calimero.cemi.CEMILData,
				 * boolean)
				 */
				/**
				 * @param waitForCon
				 */
				public void send(final CEMILData msg, final boolean waitForCon)
				{
					list.add(new Object[] { msg, otherListeners, listeners });
					synchronized (dispatcher) {
						dispatcher.notify();
					}
				}
			};
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #addLinkListener(tuwien.auto.calimero.link.event.NetworkLinkListener)
		 */
		public void addLinkListener(final NetworkLinkListener l)
		{
			listeners.add(l);
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #removeLinkListener(tuwien.auto.calimero.link.event.NetworkLinkListener)
		 */
		public void removeLinkListener(final NetworkLinkListener l)
		{
			listeners.remove(l);
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#setHopCount(int)
		 */
		public void setHopCount(final int count)
		{
			hopCount = count;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#getHopCount()
		 */
		public int getHopCount()
		{
			return hopCount;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #setKNXMedium(tuwien.auto.calimero.link.medium.KNXMediumSettings)
		 */
		public void setKNXMedium(final KNXMediumSettings settings)
		{
			ms = settings;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#getKNXMedium()
		 */
		public KNXMediumSettings getKNXMedium()
		{
			return ms;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #send(tuwien.auto.calimero.cemi.CEMILData, boolean)
		 */
		/**
		 * @param waitForCon
		 */
		public void send(final CEMILData msg, final boolean waitForCon)
		{
			list.add(new Object[] { msg, listeners, otherListeners });
			synchronized (dispatcher) {
				dispatcher.notify();
			}
		}

		private void mySend(final CEMILData msg, final EventListeners one,
			final EventListeners two)
		{
			try {
				System.out.println(DataUnitBuilder.decode(msg.getPayload(),
					msg.getDestination()));
				EventListener[] el = one.listeners();
				// send a .con for a .req
				if (msg.getMessageCode() == CEMILData.MC_LDATA_REQ) {
					final CEMILData f = (CEMILData) CEMIFactory.create(
						CEMILData.MC_LDATA_CON, msg.getPayload(), msg);
					final FrameEvent e = new FrameEvent(this, f);
					for (int i = 0; i < el.length; i++) {
						final NetworkLinkListener l = (NetworkLinkListener) el[i];
						l.confirmation(e);
					}
				}

				// forward .ind as is, but convert req. to .ind
				final CEMILData f = msg.getMessageCode() == CEMILData.MC_LDATA_IND ? msg
					: (CEMILData) CEMIFactory.create(CEMILData.MC_LDATA_IND,
						msg.getPayload(), msg);
				el = two.listeners();
				final FrameEvent e = new FrameEvent(this, f);
				for (int i = 0; i < el.length; i++) {
					final NetworkLinkListener l = (NetworkLinkListener) el[i];
					l.indication(e);
				}
			}
			catch (final KNXFormatException e1) {
				e1.printStackTrace();
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #sendRequest(tuwien.auto.calimero.KNXAddress, tuwien.auto.calimero.Priority,
		 * byte[])
		 */
		public void sendRequest(final KNXAddress dst, final Priority p, final byte[] nsdu)
		{
			try { // XXX remove the fixed ind.address
				send(new CEMILData(CEMILData.MC_LDATA_REQ,
					new IndividualAddress("1.1.1"), dst, nsdu, p), false);
			}
			catch (final KNXFormatException e) {
				e.printStackTrace();
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink
		 * #sendRequestWait(tuwien.auto.calimero.KNXAddress,
		 * tuwien.auto.calimero.Priority, byte[])
		 */
		public void sendRequestWait(final KNXAddress dst, final Priority p,
			final byte[] nsdu)
		{
			try { // XXX remove the fixed address
				send(new CEMILData(CEMILData.MC_LDATA_REQ,
					new IndividualAddress("1.1.1"), dst, nsdu, p), false);
			}
			catch (final KNXFormatException e) {
				e.printStackTrace();
			}
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#getName()
		 */
		public String getName()
		{
			return "virtual link";
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#isOpen()
		 */
		public boolean isOpen()
		{
			return !closed;
		}

		/*
		 * (non-Javadoc)
		 * @see tuwien.auto.calimero.link.KNXNetworkLink#close()
		 */
		public void close()
		{
			closed = true;
		}
	}

}
