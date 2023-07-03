#include "abstract_domain.hpp"
#include "ebpf_domain.hpp"
#include "type_domain.hpp"

template <typename Domain>
abstract_domain_t::abstract_domain_model<Domain>::abstract_domain_model(Domain abs_val)
    : m_abs_val(std::move(abs_val)) {}

template <typename Domain>
std::unique_ptr<abstract_domain_t::abstract_domain_concept>
abstract_domain_t::abstract_domain_model<Domain>::clone() const {
    std::unique_ptr<abstract_domain_t::abstract_domain_concept> res =
        std::make_unique<abstract_domain_t::abstract_domain_model<Domain>>(m_abs_val);
    return std::move(res);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::set_to_top() {
    m_abs_val.set_to_top();
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::set_to_bottom() {
    m_abs_val.set_to_bottom();
}

template <typename Domain>
bool abstract_domain_t::abstract_domain_model<Domain>::is_bottom() const {
    return m_abs_val.is_bottom();
}

template <typename Domain>
bool abstract_domain_t::abstract_domain_model<Domain>::is_top() const {
    return m_abs_val.is_top();
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
bool abstract_domain_t::abstract_domain_model<Domain>::operator<=(
    const abstract_domain_t::abstract_domain_concept& abs) const {
    return m_abs_val.operator<=(static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val);
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator|=(
    const abstract_domain_t::abstract_domain_concept& abs) {
    m_abs_val |= static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val;
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator|=(abstract_domain_t::abstract_domain_concept&& abs) {
    m_abs_val |= std::move(static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val);
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
std::unique_ptr<abstract_domain_t::abstract_domain_concept> abstract_domain_t::abstract_domain_model<Domain>::operator|(
    const abstract_domain_t::abstract_domain_concept& abs) const {
    std::unique_ptr<abstract_domain_t::abstract_domain_concept> res(
        new abstract_domain_t::abstract_domain_model<Domain>(m_abs_val.operator|(
            static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val)));
    return std::move(res);
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
std::unique_ptr<abstract_domain_t::abstract_domain_concept>
abstract_domain_t::abstract_domain_model<Domain>::operator|(abstract_domain_t::abstract_domain_concept&& abs) const {
    std::unique_ptr<abstract_domain_t::abstract_domain_concept> res(
        new abstract_domain_t::abstract_domain_model<Domain>(m_abs_val.operator|(
            std::move(static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val))));
    return std::move(res);
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
std::unique_ptr<abstract_domain_t::abstract_domain_concept> abstract_domain_t::abstract_domain_model<Domain>::operator&(
    const abstract_domain_t::abstract_domain_concept& abs) const {
    std::unique_ptr<abstract_domain_t::abstract_domain_concept> res(
        new abstract_domain_t::abstract_domain_model<Domain>(m_abs_val.operator&(
            static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val)));
    return std::move(res);
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
std::unique_ptr<abstract_domain_t::abstract_domain_concept>
abstract_domain_t::abstract_domain_model<Domain>::widen(const abstract_domain_t::abstract_domain_concept& abs) const {
    std::unique_ptr<abstract_domain_t::abstract_domain_concept> res(
        new abstract_domain_t::abstract_domain_model<Domain>(
            m_abs_val.widen(static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val)));
    return std::move(res);
}

// unsafe: if the underlying domain in abs is not Domain then it will crash
template <typename Domain>
std::unique_ptr<abstract_domain_t::abstract_domain_concept>
abstract_domain_t::abstract_domain_model<Domain>::narrow(const abstract_domain_t::abstract_domain_concept& abs) const {
    std::unique_ptr<abstract_domain_t::abstract_domain_concept> res(
        new abstract_domain_t::abstract_domain_model<Domain>(
            m_abs_val.narrow(static_cast<const abstract_domain_t::abstract_domain_model<Domain>*>(&abs)->m_abs_val)));
    return std::move(res);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const basic_block_t& bb, bool check_termination) {
    m_abs_val.operator()(bb, check_termination);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Undefined& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Bin& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Un& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const LoadMapFd& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Call& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Exit& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Jmp& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Mem& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Packet& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const LockAdd& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Assume& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::operator()(const Assert& s) {
    m_abs_val.operator()(s);
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::write(std::ostream& os) const {
    m_abs_val.write(os);
}

template <typename Domain>
std::string abstract_domain_t::abstract_domain_model<Domain>::domain_name() const {
    return m_abs_val.domain_name();
}

template <typename Domain>
crab::bound_t abstract_domain_t::abstract_domain_model<Domain>::get_instruction_count_upper_bound() {
    return m_abs_val.get_instruction_count_upper_bound();
}

template <typename Domain>
string_invariant abstract_domain_t::abstract_domain_model<Domain>::to_set() {
    return m_abs_val.to_set();
}

template <typename Domain>
void abstract_domain_t::abstract_domain_model<Domain>::set_require_check(check_require_func_t f) {
    m_abs_val.set_require_check(f);
}

abstract_domain_t::abstract_domain_t(std::unique_ptr<typename abstract_domain_t::abstract_domain_concept> concept_)
    : m_concept(std::move(concept_)) {}

template <typename Domain>
abstract_domain_t::abstract_domain_t(Domain abs_val)
    : m_concept(new abstract_domain_t::abstract_domain_model<Domain>(std::move(abs_val))) {}

abstract_domain_t::abstract_domain_t(const abstract_domain_t& o) : m_concept(o.m_concept->clone()) {}

abstract_domain_t& abstract_domain_t::operator=(const abstract_domain_t& o) {
    if (this != &o) {
        m_concept = o.m_concept->clone();
    }
    return *this;
}

void abstract_domain_t::set_to_top() { m_concept->set_to_top(); }

void abstract_domain_t::set_to_bottom() { m_concept->set_to_bottom(); }

bool abstract_domain_t::is_bottom() const { return m_concept->is_bottom(); }

bool abstract_domain_t::is_top() const { return m_concept->is_top(); }

bool abstract_domain_t::operator<=(const abstract_domain_t& abs) const {
    return m_concept->operator<=(*(abs.m_concept));
}

void abstract_domain_t::operator|=(const abstract_domain_t& abs) { m_concept->operator|=(*(abs.m_concept)); }

void abstract_domain_t::operator|=(abstract_domain_t&& abs) { m_concept->operator|=(std::move(*(abs.m_concept))); }

abstract_domain_t abstract_domain_t::operator|(const abstract_domain_t& abs) const {
    return abstract_domain_t(std::move(m_concept->operator|(*(abs.m_concept))));
}

abstract_domain_t abstract_domain_t::operator|(abstract_domain_t&& abs) const {
    return abstract_domain_t(std::move(m_concept->operator|(std::move(*(abs.m_concept)))));
}

abstract_domain_t abstract_domain_t::operator&(const abstract_domain_t& abs) const {
    return abstract_domain_t(std::move(m_concept->operator&(*(abs.m_concept))));
}

abstract_domain_t abstract_domain_t::widen(const abstract_domain_t& abs) const {
    return abstract_domain_t(std::move(m_concept->widen(*(abs.m_concept))));
}

abstract_domain_t abstract_domain_t::narrow(const abstract_domain_t& abs) const {
    return abstract_domain_t(std::move(m_concept->narrow(*(abs.m_concept))));
}

void abstract_domain_t::operator()(const basic_block_t& bb, bool check_termination) {
    m_concept->operator()(bb, check_termination);
}

void abstract_domain_t::operator()(const Undefined& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Bin& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Un& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const LoadMapFd& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Call& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Exit& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Jmp& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Mem& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Packet& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const LockAdd& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Assume& s) { m_concept->operator()(s); }

void abstract_domain_t::operator()(const Assert& s) { m_concept->operator()(s); }

void abstract_domain_t::write(std::ostream& os) const { m_concept->write(os); }

std::string abstract_domain_t::domain_name() const { return m_concept->domain_name(); }

crab::bound_t abstract_domain_t::get_instruction_count_upper_bound() { return m_concept->get_instruction_count_upper_bound(); }

string_invariant abstract_domain_t::to_set() { return m_concept->to_set(); }

void abstract_domain_t::set_require_check(check_require_func_t f) { m_concept->set_require_check(f); }

std::ostream& operator<<(std::ostream& o, const abstract_domain_t& dom) {
    dom.write(o);
    return o;
}

// REQUIRED: instantiation for supported domains
template abstract_domain_t::abstract_domain_t(crab::ebpf_domain_t);
template abstract_domain_t::abstract_domain_t(type_domain_t);
