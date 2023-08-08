package com.example.ourdiary.authentication.service;

import com.example.ourdiary.authentication.UserDetailsImpl;
import com.example.ourdiary.member.domain.Member;
import com.example.ourdiary.member.repository.MemberRepository;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final MessageSourceAccessor messageSource;

    public UserDetailsServiceImpl(MemberRepository memberRepository, MessageSourceAccessor messageSource) {
        this.memberRepository = memberRepository;
        this.messageSource = messageSource;
    }

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(messageSource.getMessage("exception.authentication.email-not-found", username)));
        return new UserDetailsImpl(member.getId(), member, member.getAuthorities().stream().map(authority -> new SimpleGrantedAuthority(authority.getAuthority().name())).toList());
    }
}
