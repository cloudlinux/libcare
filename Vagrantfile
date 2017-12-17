# -*- mode: ruby -*-
# vi: set ft=ruby :
# See Documentation/vagrant.rst for more info

Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  # Disable default shares: current dir as /vagrant and $HOME as ~/sync
  config.vm.synced_folder ENV["HOME"], "/home/vagrant/sync", disabled: true
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # Share whole git repo via nfs
  config.vm.synced_folder ".", "/home/vagrant/libcare", type: "nfs", disabled: false, mount: false

  config.vm.provider "libvirt" do |v|
    # libvirt has a strict limitation on the length of domain names:
    # Call to virDomainCreateWithFlags failed: internal error:
    # Monitor path /var/lib/libvirt/qemu/domain-kernelcare_user_ubuntu-14.04-lts-utopic-test_1470670227_d2574f4934bc0e18fefc/monitor.sock
    # too big for destination
    #
    # domain names are constructed as:
    # default_prefix + box + timestamp + random_hostname
    #
    # so keep default_prefix short (empty)
    v.default_prefix = ""
    v.random_hostname = true
  end

  config.vm.provider "parallels" do |prl|
    prl.linked_clone = true
  end

  boxes = File.readlines("#{File.dirname(__FILE__)}/vagrant_boxes").map &:strip;

  boxes.each do |box|
    # Regular development VMs
    config.vm.define "#{box}" do |b|
      b.vm.box = "ucare/#{box}"
      b.vm.box_url = "https://kernelcare.s3.amazonaws.com/ucare/vagrant/ucare/#{box}/metadata.json"
    end

    # Test VMs
    config.vm.define "#{box}-test" do |b|
      b.vm.box = "ucare/#{box}"
      b.vm.box_url = "https://kernelcare.s3.amazonaws.com/ucare/vagrant/ucare/#{box}/metadata.json"
    end
  end
end
