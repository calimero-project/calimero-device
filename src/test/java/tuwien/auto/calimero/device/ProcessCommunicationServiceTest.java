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

import java.net.InetSocketAddress;

import junit.framework.TestCase;
import tuwien.auto.calimero.GroupAddress;
import tuwien.auto.calimero.IndividualAddress;
import tuwien.auto.calimero.KNXException;
import tuwien.auto.calimero.KNXFormatException;
import tuwien.auto.calimero.KNXTimeoutException;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.StateDP;
import tuwien.auto.calimero.dptxlator.DPTXlator8BitUnsigned;
import tuwien.auto.calimero.dptxlator.DPTXlatorBoolean;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.KNXNetworkLinkIP;
import tuwien.auto.calimero.link.medium.TPSettings;
import tuwien.auto.calimero.process.ProcessCommunicator;
import tuwien.auto.calimero.process.ProcessCommunicatorImpl;
import tuwien.auto.calimero.process.ProcessEvent;
import tuwien.auto.calimero.server.Launcher;

/**
 * @author B. Malinowsky
 */
public class ProcessCommunicationServiceTest extends TestCase
{
	private static final String knxServerConfig = "server-config.xml";
	private InetSocketAddress remoteHost;

	// adjust to what is used in server-config
	//private static int serviceMode = KNXNetworkLinkIP.TUNNELING;
	private static int serviceMode = KNXNetworkLinkIP.ROUTING;

	private Launcher knxServer;

	//private BaseKnxDevice dev2;
	private final IndividualAddress addr = new IndividualAddress(1, 1, 1);
	private KNXNetworkLink link;

	private final Datapoint dp = new StateDP(new GroupAddress(1, 0, 0), "Switch", 0,
		DPTXlatorBoolean.DPT_SWITCH.getID());
	private final Datapoint dp2 = new StateDP(new GroupAddress(1, 0, 0), "Value", 0,
		DPTXlator8BitUnsigned.DPT_SCALING.getID());

	private boolean dpState = false;
	private final int dp2State = 30;

	// test Runnable return in ServiceResult
	private final ProcessCommunicationService processLogicRunnable = new ProcessCommunicationService()
	{
		public ServiceResult groupReadRequest(final ProcessEvent e)
		{
			if (e.getDestination().equals(dp.getMainAddress()))
				return new ServiceResult()
				{
					public void run()
					{
						try {
							System.out.println("handleGroupReadRequest: generating service result");
							dpState ^= true;
							((ProcessCommunicator) e.getSource()).write(
								dp.getMainAddress(), dpState);
						}
						catch (final KNXTimeoutException e) {
							e.printStackTrace();
						}
						catch (final KNXLinkClosedException e) {
							e.printStackTrace();
						}
					}
				};
			return null;
		}

		public void groupWrite(final ProcessEvent e)
		{}

		public void groupResponse(final ProcessEvent e)
		{}
	};

	// test return data byte[] in ServiceResult
	private final ProcessCommunicationService processLogic = new ProcessCommunicationService()
	{
		public ServiceResult groupReadRequest(final ProcessEvent e)
		{
			if (e.getDestination().equals(dp2.getMainAddress())) {
				DPTXlator8BitUnsigned x;
				try {
					x = new DPTXlator8BitUnsigned(dp2.getDPT());
					x.setValue(dp2State);
					return new ServiceResult(x.getData());
				}
				catch (final KNXFormatException e1) {
					e1.printStackTrace();
				}
			}
			return null;
		}

		public void groupWrite(final ProcessEvent e)
		{}

		public void groupResponse(final ProcessEvent e)
		{}
	};

	/**
	 * @param name
	 */
	public ProcessCommunicationServiceTest(final String name)
	{
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception
	{
		super.setUp();

		knxServer = new Launcher(knxServerConfig);
		final Thread t = new Thread(knxServer);
		t.start();
		Thread.sleep(1000);
		//remoteHost = Util.getServer();
		remoteHost = new InetSocketAddress("224.0.23.12", 0);
		assertEquals(knxServer.getVirtualLinks().length, 1);
		link = new KNXNetworkLinkIP(serviceMode, null, remoteHost, false,
			TPSettings.TP1);

		// XXX create KNX devices
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception
	{
		knxServer.quit();
		link.close();
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ProcessCommunicationService#groupReadRequest(
	 * tuwien.auto.calimero.process.ProcessEvent)}.
	 *
	 * @throws InterruptedException
	 * @throws KNXException
	 */
	public final void testGroupReadRequest() throws KNXException, InterruptedException
	{
		// TODO for now, works only with routing turned off on server

		final ProcessCommunicator pc = new ProcessCommunicatorImpl(link);
		String s = pc.read(dp);
		System.out.println(s);
		assertEquals(s, "on");

		s = pc.read(dp);
		System.out.println(s);
		// this is on since the server network buffer returns last value
		assertEquals(s, "on");

		s = pc.read(dp);
		System.out.println(s);
		// this is on since the server network buffer returns last value
		assertEquals(s, "on");
	}
}
