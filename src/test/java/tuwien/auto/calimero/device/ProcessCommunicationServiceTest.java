/*
    Calimero 2 - A library for KNX network access
    Copyright (c) 2011, 2016 B. Malinowsky

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
import tuwien.auto.calimero.Util;
import tuwien.auto.calimero.datapoint.Datapoint;
import tuwien.auto.calimero.datapoint.StateDP;
import tuwien.auto.calimero.dptxlator.DPTXlator8BitUnsigned;
import tuwien.auto.calimero.dptxlator.DPTXlatorBoolean;
import tuwien.auto.calimero.exception.KNXException;
import tuwien.auto.calimero.exception.KNXFormatException;
import tuwien.auto.calimero.exception.KNXTimeoutException;
import tuwien.auto.calimero.link.KNXLinkClosedException;
import tuwien.auto.calimero.link.KNXNetworkLink;
import tuwien.auto.calimero.link.KNXNetworkLinkIP;
import tuwien.auto.calimero.link.medium.KnxIPSettings;
import tuwien.auto.calimero.link.medium.TPSettings;
import tuwien.auto.calimero.process.ProcessCommunicationBase;
import tuwien.auto.calimero.process.ProcessCommunicator;
import tuwien.auto.calimero.process.ProcessCommunicatorImpl;
import tuwien.auto.calimero.process.ProcessEvent;

/**
 * @author B. Malinowsky
 */
public class ProcessCommunicationServiceTest extends TestCase
{
	private InetSocketAddress remoteHost;

//	private static int serviceMode = KNXNetworkLinkIP.TUNNELING;
	private static int serviceMode = KNXNetworkLinkIP.ROUTING;

	// client link to read/write values to a KNX device
	private KNXNetworkLink link;

	private final Datapoint dp = new StateDP(new GroupAddress(1, 1, 1), "Switch", 0,
			DPTXlatorBoolean.DPT_SWITCH.getID());
	private final Datapoint dp2 = new StateDP(new GroupAddress(1, 1, 2), "Value", 0,
			DPTXlator8BitUnsigned.DPT_SCALING.getID());

	private boolean dpState = true;
	private int dp2State = 30;

	// test Runnable return in ServiceResult
	private final ProcessCommunicationService processLogicRunnable = new ProcessCommunicationService() {
		public ServiceResult groupReadRequest(final ProcessEvent e)
		{
			if (e.getDestination().equals(dp.getMainAddress()))
				return new ServiceResult() {
					public void run()
					{
						try {
							System.out.println(
									"Runnable groupReadRequest: service result value " + dpState);
							final ProcessCommunicationBase responder = new ProcessCommunicationResponder(
									device1.getDeviceLink());
							responder.write(dp.getMainAddress(), dpState);
						}
						catch (final KNXTimeoutException e) {
							e.printStackTrace();
						}
						catch (final KNXLinkClosedException e) {
							e.printStackTrace();
						}
					}
				};
			return new ServiceResult();
		}

		public void groupWrite(final ProcessEvent e)
		{
			if (e.getDestination().equals(dp.getMainAddress())) {
				try {
					final DPTXlatorBoolean t = new DPTXlatorBoolean(dp.getDPT());
					t.setData(e.getASDU());
					dpState = t.getValueBoolean();
					System.out.println("group write value = " + dpState);
				}
				catch (final KNXFormatException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		}

		public void groupResponse(final ProcessEvent e)
		{}
	};

	// test return data byte[] in ServiceResult
	private final ProcessCommunicationService processLogic = new ProcessCommunicationService() {
		public ServiceResult groupReadRequest(final ProcessEvent e)
		{
			if (e.getDestination().equals(dp2.getMainAddress())) {
				try {
					System.out.println("groupReadRequest: service result value =" + dp2State);
					final DPTXlator8BitUnsigned x = new DPTXlator8BitUnsigned(dp2.getDPT());
					x.setValue(dp2State);
					return new ServiceResult(x.getData());
				}
				catch (final KNXFormatException e1) {
					e1.printStackTrace();
				}
			}
			return new ServiceResult();
		}

		public void groupWrite(final ProcessEvent e)
		{
			if (e.getDestination().equals(dp2.getMainAddress())) {
				try {
					final DPTXlator8BitUnsigned t = new DPTXlator8BitUnsigned(dp2.getDPT());
					t.setData(e.getASDU());
					dp2State = t.getValueUnsigned();
					System.out.println("group write value = " + dp2State);
				}
				catch (final KNXFormatException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		}

		public void groupResponse(final ProcessEvent e)
		{}
	};

	private BaseKnxDevice device1;
	private BaseKnxDevice device2;

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

		final IndividualAddress ia1 = new IndividualAddress("1.1.1");
		final IndividualAddress ia2 = new IndividualAddress("1.1.2");
		final KNXNetworkLink deviceLink1 = new KNXNetworkLinkIP(null, null, new KnxIPSettings(ia1));
		device1 = new BaseKnxDevice(ia1.toString(), ia1, deviceLink1) {
			{
				threadingPolicy = INCOMING_EVENTS_THREADED;
			}
		};
		final KNXNetworkLink deviceLink2 = new KNXNetworkLinkIP(null, null, new KnxIPSettings(ia2));
		device2 = new BaseKnxDevice(ia2.toString(), ia2, deviceLink2);

		device1.setServiceHandler(processLogicRunnable, null);
		device2.setServiceHandler(processLogic, null);

		// client link
		if (serviceMode == KNXNetworkLinkIP.TUNNELING)
			remoteHost = Util.getServer();
		else
			remoteHost = new InetSocketAddress("224.0.23.12", 0);
		link = new KNXNetworkLinkIP(serviceMode, null, remoteHost, false, TPSettings.TP1);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception
	{
		link.close();
		super.tearDown();
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ProcessCommunicationService#groupReadRequest(ProcessEvent)}
	 * .
	 *
	 * @throws InterruptedException on interrupted thread
	 * @throws KNXException
	 */
	public final void testGroupReadRequestRunnable() throws KNXException, InterruptedException
	{
		final ProcessCommunicator pc = new ProcessCommunicatorImpl(link);
		String s = pc.read(dp);
		System.out.println(s);
		assertEquals(s, "on");

		s = pc.read(dp);
		System.out.println(s);
		assertEquals(s, "on");

		s = pc.read(dp);
		System.out.println(s);
		assertEquals(s, "on");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ProcessCommunicationService#groupReadRequest(ProcessEvent)}
	 * .
	 *
	 * @throws InterruptedException on interrupted thread
	 * @throws KNXException
	 */
	public final void testGroupReadRequest() throws KNXException, InterruptedException
	{
		final ProcessCommunicator pc = new ProcessCommunicatorImpl(link);

		String s = pc.read(dp2);
		assertEquals(s, "30 %");

		s = pc.read(dp2);
		assertEquals(s, "30 %");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ProcessCommunicationService#groupWrite(ProcessEvent)} .
	 *
	 * @throws InterruptedException on interrupted thread
	 * @throws KNXException
	 */
	public final void testGroupWriteRunnable() throws KNXException, InterruptedException
	{
		final ProcessCommunicator pc = new ProcessCommunicatorImpl(link);
		pc.write(dp, "on");
		String s = pc.read(dp);
		// this is on since the server network buffer returns last value
		assertEquals(s, "on");

		pc.write(dp, "off");
		s = pc.read(dp);
		System.out.println(s);
		assertEquals(s, "off");
	}

	/**
	 * Test method for
	 * {@link tuwien.auto.calimero.device.ProcessCommunicationService#groupWrite(ProcessEvent)} .
	 *
	 * @throws InterruptedException on interrupted thread
	 * @throws KNXException
	 */
	public final void testGroupWrite() throws KNXException, InterruptedException
	{
		final ProcessCommunicator pc = new ProcessCommunicatorImpl(link);

		pc.write(dp2, "40");
		String s = pc.read(dp2);
		assertEquals(s, "40 %");

		pc.write(dp2, "30");
		s = pc.read(dp2);
		assertEquals(s, "30 %");
	}
}
