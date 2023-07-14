<?php
/**
 * Indera EPP registrar module for FOSSBilling (https://fossbilling.org/)
 *
 * Written in 2023 by Taras Kondratyuk (https://getpinga.com)
 * Based on Generic EPP with DNSsec Registrar Module for WHMCS written in 2019 by Lilian Rudenco (info@xpanel.com)
 * Work of Lilian Rudenco is under http://opensource.org/licenses/afl-3.0.php Academic Free License (AFL 3.0)
 *
 * @license MIT
 */
class Registrar_Adapter_FRED extends Registrar_AdapterAbstract
{
    public $config = array();
    public $socket;
    public $isLogined;

    public function __construct($options)
    {
        if(isset($options['username'])) {
            $this->config['username'] = $options['username'];
        }
        if(isset($options['password'])) {
            $this->config['password'] = $options['password'];
        }
        if(isset($options['host'])) {
            $this->config['host'] = $options['host'];
        }
        if(isset($options['port'])) {
            $this->config['port'] = $options['port'];
        }
        if(isset($options['registrarprefix'])) {
            $this->config['registrarprefix'] = $options['registrarprefix'];
        }
        if(isset($options['ssl_cert'])) {
            $this->config['ssl_cert'] = $options['ssl_cert'];
        }
        if(isset($options['ssl_key'])) {
            $this->config['ssl_key'] = $options['ssl_key'];
        }
        if(isset($options['ssl_ca'])) {
            $this->config['ssl_ca'] = $options['ssl_ca'];
        }
        if(isset($options['use_tls_12'])) {
            $this->config['use_tls_12'] = (bool)$options['use_tls_12'];
        } else {
            $this->config['use_tls_12'] = false;
        }
    }

    public function getTlds()
    {
        return array();
    }
    
    public static function getConfig()
    {
        return array(
            'label' => 'An EPP registry module, designed for FRED EPP server, allows registrars to manage and register domain names using the Extensible Provisioning Protocol (EPP). All details below are typically provided by the domain registry and are used to authenticate your account when connecting to the FRED EPP server.',
            'form'  => array(
                'username' => array('text', array(
                    'label' => 'EPP Server Username',
                    'required' => true,
                ),
                ),
                'password' => array('password', array(
                    'label' => 'EPP Server Password',
                    'required' => true,
                ),
                ),
                'host' => array('text', array(
                    'label' => 'EPP Server Host',
                    'required' => true,
                ),
                ),
                'port' => array('text', array(
                    'label' => 'EPP Server Port',
                    'required' => true,
                ),
                ),
                'registrarprefix' => array('text', array(
                    'label' => 'Registrar Prefix',
                    'required' => true,
                ),
                ),
                'ssl_cert' => array('text', array(
                    'label' => 'SSL Certificate Path',
                    'required' => true,
                ),
                ),
                'ssl_key' => array('text', array(
                    'label' => 'SSL Key Path',
                    'required' => true,
                ),
                ),
                'ssl_ca' => array('text', array(
                    'label' => 'SSL CA Path',
                    'required' => false,
                ),
                ),
                'use_tls_12' => array('radio', array(
                     'multiOptions' => array('1'=>'Yes', '0'=>'No'),
                     'label' => 'Use TLS 1.2 instead of 1.3',
                 ),
                 ),
            ),
        );
    }
    
    public function isDomaincanBeTransferred(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Checking if domain can be transferred: ' . $domain->getName());
        return true;
    }

    public function isDomainAvailable(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Checking domain availability: ' . $domain->getName());
		$s	= $this->connect();
		$this->login();
		$from = $to = array();
		$from[] = '/{{ name }}/';
		$to[] = htmlspecialchars($domain->getName());
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1) , 3));
		$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-check-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<command>
   <check>
      <domain:check xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
	      <domain:name>{{ name }}</domain:name>
      </domain:check>
   </check>
   <clTRID>{{ clTRID }}</clTRID>
</command>
</epp>');

		$r = $this->write($xml, __FUNCTION__);

		$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->chkData;
		$reason = (string)$r->cd[0]->reason;

		if ($reason)
		{
			return false;
		} else {
			return true;
		}
		if (!empty($s))
		{
			$this->logout();
		}

        return true;
    }

    public function modifyNs(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Modifying nameservers: ' . $domain->getName());
        $this->getLog()->debug('Ns1: ' . $domain->getNs1());
        $this->getLog()->debug('Ns2: ' . $domain->getNs2());
        $this->getLog()->debug('Ns3: ' . $domain->getNs3());
        $this->getLog()->debug('Ns4: ' . $domain->getNs4());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->infData;
			$nsset = (string)$r->nsset;

			if (isset($nsset) && $nsset !== '') {
			   $from = $to = array();
			   $from[] = '/{{ name }}/';
			   $to[] = $nsset;
			   $from[] = '/{{ clTRID }}/';
			   $clTRID = str_replace('.', '', round(microtime(1), 3));
			   $to[] = htmlspecialchars($this->config['registrarprefix'] . '-host-info-' . $clTRID);
			   $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<command>
   <info>
      <nsset:info xmlns:nsset="http://www.nic.cz/xml/epp/nsset-1.2"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/nsset-1.2 nsset-1.2.2.xsd">
         <nsset:id>{{ name }}</nsset:id>
      </nsset:info>
   </info>
   <clTRID>{{ clTRID }}</clTRID>
</command>
</epp>');
			   $r = $this->write($xml, __FUNCTION__);
			   $r = $r->response->resData->children('http://www.nic.cz/xml/epp/nsset-1.2')->infData;

			   $add = $rem = array();
			   $i = 0;
			   foreach($r->ns as $ns) {
			      $i++;
			      $ns = (string)$ns->name;
			      if (!$ns) {
			         continue;
			      }

			      $rem["ns{$i}"] = $ns;
			   }

			   foreach (range(1, 4) as $i) {
			      $k = "getNs$i";
			      $v = $domain->{$k}();
			      if (!$v) {
			         continue;
			      }

			      if ($k0 = array_search($v, $rem)) {
			         unset($rem[$k0]);
			      } else {
			         $add["ns$i"] = $v;
			      }
			   }

			   if (!empty($add) || !empty($rem)) {
			      $from = $to = array();
			      $text = '';
			      foreach($add as $k => $v) {
			         $text.= '<nsset:name>' . $v . '</nsset:name>' . "\n";
			      }

			      $from[] = '/{{ add }}/';
			      $to[] = (empty($text) ? '' : "<nsset:add><nsset:ns>\n{$text}</nsset:ns></nsset:add>\n");
			      $text = '';
			      foreach($rem as $k => $v) {
			         $text.= '<nsset:name>' . $v . '</nsset:name>' . "\n";
			      }

			      $from[] = '/{{ rem }}/';
			      $to[] = (empty($text) ? '' : "<nsset:rem>\n{$text}</nsset:rem>\n");
			      $from[] = '/{{ name }}/';
			      $to[] = $nsset;
			      $from[] = '/{{ clTRID }}/';
			      $clTRID = str_replace('.', '', round(microtime(1), 3));
			      $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-update-' . $clTRID);
			      $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
<command>
   <update>
      <nsset:update xmlns:nsset="http://www.nic.cz/xml/epp/nsset-1.2"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/nsset-1.2 nsset-1.2.2.xsd">
         <nsset:id>{{ name }}</nsset:id>
		{{ add }}
		{{ rem }}
      </nsset:update>
   </update>
   <clTRID>{{ clTRID }}</clTRID>
</command>
</epp>');
			     $r = $this->write($xml, __FUNCTION__);
			   }
			} else {
			   $from = $to = array();
			   $from[] = '/{{ name }}/';
			   $to[] = htmlspecialchars($domain->getName());
			   $from[] = '/{{ clTRID }}/';
			   $clTRID = str_replace('.', '', round(microtime(1), 3));
			   $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			   $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			   $r = $this->write($xml, __FUNCTION__);
			   $r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->infData;
			   $reg_contact = (string)$r->registrant;
			
			   $add = array();
			   $i = 0;

			   foreach (range(1, 4) as $i) {
			      $k = "getNs$i";
			      $v = $domain->{$k}();
			      if (!$v) {
			         continue;
			      }
			      $add["ns$i"] = $v;
			   }

			   if (!empty($add)) {
			      $from = $to = array();
			      $text = '';
			      foreach($add as $k => $v) {
			         $text.= '<nsset:name>' . $v . '</nsset:name>' . "\n";
			      }

			      $from[] = '/{{ add }}/';
			      $to[] = (empty($text) ? '' : "<nsset:ns>\n{$text}</nsset:ns>\n");
			      $text = '';
			      $from[] = '/{{ id }}/';
			      $nid = strtoupper($this->generateRandomString());
			      $to[] = $nid;
			      $from[] = '/{{ name }}/';
			      $to[] = $reg_contact;
			      $from[] = '/{{ clTRID }}/';
			      $clTRID = str_replace('.', '', round(microtime(1), 3));
			      $to[] = htmlspecialchars($this->config['registrarprefix'] . '-host-create-' . $clTRID);
			      $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <command>
      <create>
         <nsset:create xmlns:nsset="http://www.nic.cz/xml/epp/nsset-1.2"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/nsset-1.2 nsset-1.2.2.xsd">
            <nsset:id>{{ id }}</nsset:id>
		{{ add }}
            <nsset:tech>{{ name }}</nsset:tech>
            <nsset:reportlevel>1</nsset:reportlevel>
         </nsset:create>
      </create>
      <clTRID>{{ clTRID }}</clTRID>
   </command>
</epp>');
			     $r = $this->write($xml, __FUNCTION__); file_put_contents('/tmp/test1.log', print_r($r,true));
			     $r = $r->response->resData->children('http://www.nic.cz/xml/epp/nsset-1.2')->creData;
				
			     $nsset_id = (string)$r->id;
				//update domain here with new nsset id
			   }
			   
			}
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function transferDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Transfering domain: ' . $domain->getName());
        $this->getLog()->debug('Epp code: ' . $domain->getEpp());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ authInfo_pw }}/';
			$to[] = htmlspecialchars($domain->getEpp());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-transfer-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<transfer op="request">
	  <domain:transfer xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
		<domain:authInfo>{{ authInfo_pw }}</domain:authInfo>
	  </domain:transfer>
	</transfer>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function getDomainDetails(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Getting whois: ' . $domain->getName());

        if(!$domain->getRegistrationTime()) {
            $domain->setRegistrationTime(time());
        }
        if(!$domain->getExpirationTime()) {
            $years = $domain->getRegistrationPeriod();
            $domain->setExpirationTime(strtotime("+$years year"));
        }
        return $domain;
    }

    public function deleteDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Removing domain: ' . $domain->getName());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-delete-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<delete>
	  <domain:delete xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:delete>
	</delete>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function registerDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Registering domain: ' . $domain->getName(). ' for '.$domain->getRegistrationPeriod(). ' years');
		$client = $domain->getContactRegistrar();

		$return = array();
		try {
			$s = $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-check-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <check>
      <domain:check xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:check>
    </check>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->chkData;
			$reason = (string)$r->cd[0]->reason;
			if (!$reason) {
				$reason = 'Domain is not available';
			}

			if (0 == (int)$r->cd[0]->name->attributes()->avail) {
				throw new exception($r->cd[0]->name . ' ' . $reason);
			}
			
			// contact:create
			$from = $to = array();
			$from[] = '/{{ id }}/';
			$c_id = strtoupper($this->generateRandomString());
			$to[] = $c_id;
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($client->getFirstName() . ' ' . $client->getLastName());
			$from[] = '/{{ org }}/';
			$to[] = htmlspecialchars($client->getCompany());
			$from[] = '/{{ street1 }}/';
			$to[] = htmlspecialchars($client->getAddress1());
			$from[] = '/{{ city }}/';
			$to[] = htmlspecialchars($client->getCity());
			$from[] = '/{{ state }}/';
			$to[] = htmlspecialchars($client->getState());
			$from[] = '/{{ postcode }}/';
			$to[] = htmlspecialchars($client->getZip());
			$from[] = '/{{ country }}/';
			$to[] = htmlspecialchars($client->getCountry());
			$from[] = '/{{ phonenumber }}/';
			$to[] = htmlspecialchars('+'.$client->getTelCc().'.'.$client->getTel());
			$from[] = '/{{ email }}/';
			$to[] = htmlspecialchars($client->getEmail());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-contact-create-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
	<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
	  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
	  <command>
		<create>
		  <contact:create xmlns:contact="http://www.nic.cz/xml/epp/contact-1.6"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/contact-1.6 contact-1.6.2.xsd">
			<contact:id>{{ id }}</contact:id>
			<contact:postalInfo>
			  <contact:name>{{ name }}</contact:name>
			  <contact:org>{{ org }}</contact:org>
			  <contact:addr>
				<contact:street>{{ street1 }}</contact:street>
				<contact:street></contact:street>
				<contact:street></contact:street>
				<contact:city>{{ city }}</contact:city>
				<contact:sp>{{ state }}</contact:sp>
				<contact:pc>{{ postcode }}</contact:pc>
				<contact:cc>{{ country }}</contact:cc>
			  </contact:addr>
			</contact:postalInfo>
			<contact:voice>{{ phonenumber }}</contact:voice>
			<contact:fax></contact:fax>
			<contact:email>{{ email }}</contact:email>
		  </contact:create>
		</create>
		<clTRID>{{ clTRID }}</clTRID>
	  </command>
	</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/contact-1.6')->creData;
			$contacts = $r->id;

			//host create
			$from = $to = array();
			$from[] = '/{{ nsid }}/';
			$c_id = strtoupper($this->generateRandomString());
			$to[] = $c_id;
			$ns = '';
			for ($i = 1; $i <= 4; $i++) {
    			$nsMethod = 'getNs'.$i;
 			   if (method_exists($domain, $nsMethod) && $domain->$nsMethod() !== null && $domain->$nsMethod() !== '') {
  			      $ns .= "<nsset:ns>
  			                 <nsset:name>" . $domain->$nsMethod() . "</nsset:name>
  			              </nsset:ns>";
 						}
			}
			$from[] = '/{{ nsnames }}/';
			$to[] = $ns;			
			$from[] = '/{{ nstech }}/';
			$to[] = $contacts;
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-host-create-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <command>
      <create>
         <nsset:create xmlns:nsset="http://www.nic.cz/xml/epp/nsset-1.2"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/nsset-1.2 nsset-1.2.2.xsd">
            <nsset:id>{{ nsid }}</nsset:id>
            {{ nsnames }}
            <nsset:tech>{{ nstech }}</nsset:tech>
            <nsset:reportlevel>0</nsset:reportlevel>
         </nsset:create>
      </create>
      <clTRID>{{ clTRID }}</clTRID>
   </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);

			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ period }}/';
			$to[] = htmlspecialchars($domain->getRegistrationPeriod());
			$from[] = '/{{ nsid }}/';
			$to[] = $c_id;
			$from[] = '/{{ cID_1 }}/';
			$to[] = htmlspecialchars($contacts);
			$from[] = '/{{ cID_2 }}/';
			$to[] = htmlspecialchars($contacts);
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-create-' . $clTRID);
			$from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
			$to[] = '';
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <command>
      <create>
         <domain:create xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
            <domain:name>{{ name }}</domain:name>
            <domain:period unit="y">{{ period }}</domain:period>
            <domain:nsset>{{ nsid }}</domain:nsset>
            <domain:registrant>{{ cID_1 }}</domain:registrant>
            <domain:admin>{{ cID_2 }}</domain:admin>
         </domain:create>
      </create>
      <clTRID>{{ clTRID }}</clTRID>
   </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function renewDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Renewing domain: ' . $domain->getName());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->infData;
			$expDate = (string)$r->exDate;
			$expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ expDate }}/';
			$to[] = htmlspecialchars($expDate);
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-renew-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<renew>
	  <domain:renew xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
		<domain:curExpDate>{{ expDate }}</domain:curExpDate>
		<domain:period unit="y">1</domain:period>
	  </domain:renew>
	</renew>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function modifyContact(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Updating contact info: ' . $domain->getName());
		$client = $domain->getContactRegistrar();
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
        <domain:name>{{ name }}</domain:name>
      </domain:info>
    </info>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->infData;
			$registrant = (string)$r->registrant;
			$from = $to = array();
			$from[] = '/{{ id }}/';
			$to[] = $registrant;
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($client->getFirstName() . ' ' . $client->getLastName());
			$from[] = '/{{ org }}/';
			$to[] = htmlspecialchars($client->getCompany());
			$from[] = '/{{ street1 }}/';
			$to[] = htmlspecialchars($client->getAddress1());
			$from[] = '/{{ street2 }}/';
			$to[] = htmlspecialchars($client->getAddress2());
			$from[] = '/{{ city }}/';
			$to[] = htmlspecialchars($client->getCity());
			$from[] = '/{{ state }}/';
			$to[] = htmlspecialchars($client->getState());
			$from[] = '/{{ postcode }}/';
			$to[] = htmlspecialchars($client->getZip());
			$from[] = '/{{ country }}/';
			$to[] = htmlspecialchars($client->getCountry());
			$from[] = '/{{ phonenumber }}/';
			$to[] = htmlspecialchars('+'.$client->getTelCc().'.'.$client->getTel());
			$from[] = '/{{ email }}/';
			$to[] = htmlspecialchars($client->getEmail());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-contact-update-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
  <epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
    <command>
      <update>
        <contact:update xmlns:contact="http://www.nic.cz/xml/epp/contact-1.6"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/contact-1.6 contact-1.6.2.xsd">
          <contact:id>{{ id }}</contact:id>
          <contact:chg>
            <contact:postalInfo>
			  <contact:name>{{ name }}</contact:name>
              <contact:org>{{ org }}</contact:org>
              <contact:addr>
                <contact:street>{{ street1 }}</contact:street>
                <contact:street>{{ street2 }}</contact:street>
                <contact:street></contact:street>
                <contact:city>{{ city }}</contact:city>
                <contact:sp>{{ state }}</contact:sp>
                <contact:pc>{{ postcode }}</contact:pc>
                <contact:cc>{{ country }}</contact:cc>
              </contact:addr>
            </contact:postalInfo>
            <contact:voice>{{ phonenumber }}</contact:voice>
            <contact:fax></contact:fax>    
	    <contact:email>{{ email }}</contact:email>
          </contact:chg>
        </contact:update>
      </update>
      <clTRID>{{ clTRID }}</clTRID>
    </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }
    
    public function enablePrivacyProtection(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Enabling Privacy protection: ' . $domain->getName());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->infData;
			$dcontact = array();
			$dcontact['registrant'] = (string)$r->registrant;
			foreach($r->contact as $e) {
				$type = (string)$e->attributes()->type;
				$dcontact[$type] = (string)$e;
			}

			$contact = array();
			foreach($dcontact as $id) {
				if (isset($contact[$id])) {
					continue;
				}
				$from = $to = array();
				$from[] = '/{{ id }}/';
				$to[] = htmlspecialchars($id);
				$from[] = '/{{ flag }}/';
				$to[] = 0;
				$from[] = '/{{ clTRID }}/';
				$clTRID = str_replace('.', '', round(microtime(1) , 3));
				$to[] = htmlspecialchars($this->config['registrarprefix'] . '-contact-update-' . $clTRID);
				$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <command>
      <update>
         <contact:update xmlns:contact="http://www.nic.cz/xml/epp/contact-1.6"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/contact-1.6 contact-1.6.2.xsd">
            <contact:id>{{ id }}</contact:id>
            <contact:chg>
			  <contact:disclose flag="{{ flag }}">
				<contact:addr/>
				<contact:voice/>
				<contact:fax/>
				<contact:email/>
			  </contact:disclose>
            </contact:chg>
         </contact:update>
      </update>
      <clTRID>{{ clTRID }}</clTRID>
   </command>
</epp>');
				$r = $this->write($xml, __FUNCTION__);
			}
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }
    
    public function disablePrivacyProtection(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Disabling Privacy protection: ' . $domain->getName());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<info>
	  <domain:info xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
		<domain:name>{{ name }}</domain:name>
	  </domain:info>
	</info>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$r = $r->response->resData->children('http://www.nic.cz/xml/epp/domain-1.4')->infData;
			$dcontact = array();
			$dcontact['registrant'] = (string)$r->registrant;
			foreach($r->contact as $e) {
				$type = (string)$e->attributes()->type;
				$dcontact[$type] = (string)$e;
			}

			$contact = array();
			foreach($dcontact as $id) {
				if (isset($contact[$id])) {
					continue;
				}
				$from = $to = array();
				$from[] = '/{{ id }}/';
				$to[] = htmlspecialchars($id);
				$from[] = '/{{ flag }}/';
				$to[] = 1;
				$from[] = '/{{ clTRID }}/';
				$clTRID = str_replace('.', '', round(microtime(1) , 3));
				$to[] = htmlspecialchars($this->config['registrarprefix'] . '-contact-update-' . $clTRID);
				$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <command>
      <update>
         <contact:update xmlns:contact="http://www.nic.cz/xml/epp/contact-1.6"
          xsi:schemaLocation="http://www.nic.cz/xml/epp/contact-1.6 contact-1.6.2.xsd">
            <contact:id>{{ id }}</contact:id>
            <contact:chg>
			  <contact:disclose flag="{{ flag }}">
				<contact:addr/>
				<contact:voice/>
				<contact:fax/>
				<contact:email/>
			  </contact:disclose>
            </contact:chg>
         </contact:update>
      </update>
      <clTRID>{{ clTRID }}</clTRID>
   </command>
</epp>');
				$r = $this->write($xml, __FUNCTION__);
			}
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function getEpp(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Retrieving domain transfer code: ' . $domain->getName());
		$return = array();
		try {
			$s	= $this->connect();
			$this->login();
			$from = $to = array();
			$from[] = '/{{ name }}/';
			$to[] = htmlspecialchars($domain->getName());
			$from[] = '/{{ clTRID }}/';
			$clTRID = str_replace('.', '', round(microtime(1), 3));
			$to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
			$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <extension>
      <fred:extcommand xmlns:fred="http://www.nic.cz/xml/epp/fred-1.5"
       xsi:schemaLocation="http://www.nic.cz/xml/epp/fred-1.5 fred-1.5.0.xsd">
         <fred:sendAuthInfo>
            <domain:sendAuthInfo xmlns:domain="http://www.nic.cz/xml/epp/domain-1.4"
             xsi:schemaLocation="http://www.nic.cz/xml/epp/domain-1.4 domain-1.4.2.xsd">
               <domain:name>{{ name }}</domain:name>
            </domain:sendAuthInfo>
         </fred:sendAuthInfo>
         <fred:clTRID>{{ clTRID }}</fred:clTRID>
      </fred:extcommand>
   </extension>
</epp>');
			$r = $this->write($xml, __FUNCTION__);
			$eppcode = 'sent to registrant';

			if (!empty($s)) {
					$this->logout();
				}
			return $eppcode;
		}

		catch(exception $e) {
			$return = array(
				'error' => $e->getMessage()
			);
		}

		if (!empty($s)) {
			$this->logout();
		}

		return $return;
    }

    public function lock(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Locking domain: ' . $domain->getName());
		//Registry does not support lock/unlock
		//return $return;
    }

    public function unlock(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Unlocking: ' . $domain->getName());
		//Registry does not support lock/unlock
		//return $return;
    }

	public function connect()
	{
		$host = $this->config['host'];
		$port = $this->config['port'];
		$timeout = 30;
		
		$opts = array(
			'ssl' => array(
				'verify_peer' => false,
				'verify_peer_name' => false,
				'verify_host' => false,
				'allow_self_signed' => true,
				'local_cert' => $this->config['ssl_cert'],
				'local_pk' => $this->config['ssl_key']
			)
		);
		$context = stream_context_create($opts);
		if ($this->config['use_tls_12'] === true) {
 		   $tls = 'tlsv1.2';
		} else {
 		   $tls = 'tlsv1.3';
		}
		$this->socket = stream_socket_client($tls."://{$host}:{$port}", $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);

		if (!$this->socket) {
			throw new exception("Cannot connect to server '{$host}': {$errmsg}");
		}

		return $this->read();
	}

	public function login()
	{
		$from = $to = array();
		$from[] = '/{{ clID }}/';
		$to[] = htmlspecialchars($this->config['username']);
		$from[] = '/{{ pw }}/';
		$to[] = $this->config['password'];
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($this->config['registrarprefix'] . '-login-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="utf-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
   <command>
      <login>
         <clID>{{ clID }}</clID>
         <pw><![CDATA[{{ pw }}]]></pw>
         <options>
            <version>1.0</version>
            <lang>en</lang>
         </options>
         <svcs>
            <objURI>http://www.nic.cz/xml/epp/contact-1.6</objURI>
            <objURI>http://www.nic.cz/xml/epp/nsset-1.2</objURI>
            <objURI>http://www.nic.cz/xml/epp/domain-1.4</objURI>
            <objURI>http://www.nic.cz/xml/epp/keyset-1.3</objURI>
            <svcExtension>
               <extURI>http://www.nic.cz/xml/epp/enumval-1.2</extURI>
            </svcExtension>
         </svcs>
      </login>
      <clTRID>{{ clTRID }}</clTRID>
   </command>
</epp>');
		$r = $this->write($xml, __FUNCTION__);
		$this->isLogined = true;
		return true;
	}

	public function logout()
	{
		if (!$this->isLogined) {
			return true;
		}

		$from = $to = array();
		$from[] = '/{{ clTRID }}/';
		$clTRID = str_replace('.', '', round(microtime(1), 3));
		$to[] = htmlspecialchars($this->config['registrarprefix'] . '-logout-' . $clTRID);
		$xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
	<logout/>
	<clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
		$r = $this->write($xml, __FUNCTION__);
		$this->isLogined = false;
		return true;
	}

	public function read()
	{
	    $hdr = stream_get_contents($this->socket, 4);
	    if ($hdr === false) {
		throw new exception('Connection appears to have closed.');
	    }
	    if (strlen($hdr) < 4) {
		throw new exception('Failed to read header from the connection.');
	    }
	    $unpacked = unpack('N', $hdr);
	    $xml = fread($this->socket, ($unpacked[1] - 4));
	    $xml = preg_replace('/></', ">\n<", $xml);      
	    return $xml;
	}

	public function write($xml)
	{
	    if (fwrite($this->socket, pack('N', (strlen($xml) + 4)) . $xml) === false) {
		throw new exception('Error writing to the connection.');
	    }
	    $r = simplexml_load_string($this->read());
            if (isset($r->response) && $r->response->result->attributes()->code >= 2000) {
                throw new exception($r->response->result->msg);
            }
		return $r;
	}

	public function disconnect()
	{
		$result = fclose($this->socket);
		if (!$result) {
 			throw new exception('Error closing the connection.');
		}
		$this->socket = null;
		return $result;
	}

	function generateObjectPW($objType = 'none')
	{
		$result = '';
		$uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		$lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
		$numbers = "1234567890";
		$specialSymbols = "!=+-";
		$minLength = 13;
		$maxLength = 13;
		$length = mt_rand($minLength, $maxLength);

		// Include at least one character from each set
		$result .= $uppercaseChars[mt_rand(0, strlen($uppercaseChars) - 1)];
		$result .= $lowercaseChars[mt_rand(0, strlen($lowercaseChars) - 1)];
		$result .= $numbers[mt_rand(0, strlen($numbers) - 1)];
		$result .= $specialSymbols[mt_rand(0, strlen($specialSymbols) - 1)];

		// Append random characters to reach the desired length
		while (strlen($result) < $length) {
			$chars = $uppercaseChars . $lowercaseChars . $numbers . $specialSymbols;
			$result .= $chars[mt_rand(0, strlen($chars) - 1)];
		}

		return 'aA1' . $result;
	}
	
	public function generateRandomString() 
	{
		$characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
		$randomString = '';
		for ($i = 0; $i < 12; $i++) {
			$randomString .= $characters[rand(0, strlen($characters) - 1)];
		}
		return $randomString;
	}
}
