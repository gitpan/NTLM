#!/usr/bin/perl

use ExtUtils::MakeMaker;

# 

WriteMakefile(
    'NAME'		=> 'Authen::NTLM',
    'DIR'		=> ['DES', 'MD4'],
    'VERSION_FROM'	=> 'NTLM.pm',
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      ('AUTHOR'     => 'Mark Bush <Mark.Bush@bushnet.demon.co.uk>') : ()),
);
