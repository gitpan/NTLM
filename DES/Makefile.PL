#!/usr/bin/perl

use ExtUtils::MakeMaker;

# 

WriteMakefile(
    'NAME'		=> 'Authen::NTLM::DES',
    'VERSION_FROM'	=> 'DES.pm',
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      ('AUTHOR'     => 'Mark Bush <Mark.Bush@bushnet.demon.co.uk>') : ()),
);
